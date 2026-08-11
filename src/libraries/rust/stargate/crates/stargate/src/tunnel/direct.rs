// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method};
use quinn::{Connection, Endpoint};
use tracing::info_span;
use url::Url;

use stargate_protocol::TunnelTransportProtocol;
use stargate_protocol::tunnel_contract::{HEADER_INPUT_TOKENS, HEADER_MODEL, HEADER_REQUEST_ID};

use crate::auth::WorkerAuthenticator;
use crate::routing_state::RegistrationGeneration;

use super::body::OpenStreamingRequest;
use super::connection::{TunnelConnection, TunnelConnectionSet};
use super::endpoint::build_client_config;
use super::http3::build_h3_client_connection;
use super::raw_quic::RawQuicConnectionHandle;
use super::request::OpenTunnelRequest;
use super::webtransport::build_webtransport_client_connection;
use super::{QuicTunnelConfig, StreamingResponse};

pub struct QuicHttpProxy {
    pub(super) config: QuicTunnelConfig,
    client_endpoints: RwLock<ClientEndpoints>,
    pub(super) metrics: OnceLock<Arc<crate::metrics::StargateMetrics>>,
    server_identity_not_after: AtomicI64,
    pub(super) authenticator: Arc<dyn WorkerAuthenticator>,
}

struct ClientEndpoints {
    endpoint_v4: Arc<Endpoint>,
    endpoint_v6: Arc<Endpoint>,
}

impl ClientEndpoints {
    fn build(client_config: quinn::ClientConfig) -> Result<Self> {
        let mut endpoint_v4 = Endpoint::client("0.0.0.0:0".parse()?)?;
        let mut endpoint_v6 = Endpoint::client("[::]:0".parse()?)?;
        endpoint_v4.set_default_client_config(client_config.clone());
        endpoint_v6.set_default_client_config(client_config);
        Ok(Self {
            endpoint_v4: Arc::new(endpoint_v4),
            endpoint_v6: Arc::new(endpoint_v6),
        })
    }

    fn close(&self) {
        self.endpoint_v4
            .close(0u32.into(), b"TLS trust configuration replaced");
        self.endpoint_v6
            .close(0u32.into(), b"TLS trust configuration replaced");
    }
}

impl QuicHttpProxy {
    pub fn new(
        config: QuicTunnelConfig,
        authenticator: Arc<dyn WorkerAuthenticator>,
    ) -> Result<Self> {
        ensure!(
            config.direct_quic_connections > 0,
            "direct_quic_connections must be > 0"
        );
        let client_config = build_client_config(
            config.tls_cert_pem.as_deref(),
            config.quic_insecure,
            config.tunnel_protocol,
        )?;
        let client_endpoints = ClientEndpoints::build(client_config)?;
        let server_identity_not_after =
            stargate_tls::server_identity_effective_validity(&config.server_tls_identity)?
                .map_or(i64::MAX, |validity| validity.not_after_unix_seconds);

        Ok(Self {
            config,
            client_endpoints: RwLock::new(client_endpoints),
            metrics: OnceLock::new(),
            server_identity_not_after: AtomicI64::new(server_identity_not_after),
            authenticator,
        })
    }

    pub(crate) fn set_metrics(&self, metrics: Arc<crate::metrics::StargateMetrics>) {
        if self.metrics.set(metrics.clone()).is_ok() {
            let expiry = self.server_identity_not_after.load(Ordering::Acquire);
            if expiry != i64::MAX {
                metrics.set_tls_certificate_expiry(expiry);
            }
        }
    }

    pub(crate) fn update_server_identity_expiry_from_validity(
        &self,
        validity: Option<&stargate_tls::CertificateValidity>,
    ) {
        let expiry = validity.map_or(i64::MAX, |validity| validity.not_after_unix_seconds);
        self.server_identity_not_after
            .store(expiry, Ordering::Release);
        if expiry != i64::MAX
            && let Some(metrics) = self.metrics.get()
        {
            metrics.set_tls_certificate_expiry(expiry);
        }
    }

    pub(crate) fn tls_identity_is_ready(&self) -> bool {
        let expiry = self.server_identity_not_after.load(Ordering::Acquire);
        expiry == i64::MAX
            || (expiry >= 0
                && std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .is_ok_and(|now| now.as_secs() <= expiry as u64))
    }

    pub(crate) async fn run_client_trust_reloader(
        self: Arc<Self>,
        mut reloader: stargate_tls::ClientTrustReloader,
        poll_interval: Duration,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        ensure!(
            !poll_interval.is_zero(),
            "TLS reload interval must be positive"
        );
        let mut interval = tokio::time::interval(poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return Ok(()),
                _ = interval.tick() => {
                    match reloader.load_candidate() {
                        Ok(None) => {}
                        Ok(Some(candidate)) => {
                            let activation = (|| -> Result<ClientEndpoints> {
                                let client_config = build_client_config(
                                    Some(&candidate),
                                    false,
                                    self.config.tunnel_protocol,
                                )?;
                                let replacement = ClientEndpoints::build(client_config)?;
                                let mut active = self.client_endpoints.write().map_err(|_| {
                                    anyhow!("TLS client endpoint lock poisoned")
                                })?;
                                Ok(std::mem::replace(&mut *active, replacement))
                            })();
                            match activation {
                                Ok(previous) => {
                                    reloader.commit(candidate);
                                    previous.close();
                                    if let Some(metrics) = self.metrics.get() {
                                        metrics.tls_reloads_total("client_trust", "success").inc();
                                    }
                                    tracing::info!(component = "stargate", material_type = "client_trust", result = "success", "TLS material reloaded; existing client connections closed");
                                }
                                Err(error) => {
                                    if let Some(metrics) = self.metrics.get() {
                                        metrics.tls_reloads_total("client_trust", "rejected").inc();
                                    }
                                    tracing::warn!(component = "stargate", material_type = "client_trust", result = "rejected", error = %error, "TLS material activation rejected; retaining last-known-good configuration");
                                }
                            }
                        }
                        Err(error) => {
                            if let Some(metrics) = self.metrics.get() {
                                metrics.tls_reloads_total("client_trust", "rejected").inc();
                            }
                            tracing::warn!(
                                component = "stargate",
                                material_type = "client_trust",
                                result = "rejected",
                                error = %error,
                                "TLS material reload rejected; retaining last-known-good configuration"
                            );
                        }
                    }
                }
            }
        }
    }

    pub(crate) async fn connect_direct_registration(
        &self,
        registration: &RegistrationGeneration,
    ) -> Result<()> {
        ensure!(
            !registration.reverse_tunnel(),
            "cannot connect directly for a reverse-tunnel registration"
        );
        let tunnel_connections = registration.tunnel_connections();
        ensure!(
            tunnel_connections.is_active(),
            "registration generation ended before direct tunnel connected"
        );
        let connections = self
            .connect_direct_set(registration.inference_server_url())
            .await?;
        ensure!(
            tunnel_connections.install_direct(connections),
            "registration generation ended before direct tunnel connected"
        );
        Ok(())
    }

    async fn connect_direct_set(&self, target_url: &str) -> Result<TunnelConnectionSet> {
        let mut connections = Vec::with_capacity(self.config.direct_quic_connections);
        // Opening the configured set up front lets hot-path requests distribute
        // stream creation across QUIC connections instead of piling onto one.
        for _ in 0..self.config.direct_quic_connections {
            connections.push(self.connect_direct_connection(target_url).await?);
        }
        TunnelConnectionSet::new(connections)
    }

    pub(super) async fn connect_direct_connection(
        &self,
        target_url: &str,
    ) -> Result<TunnelConnection> {
        let addr = parse_quic_addr(target_url)?;
        let endpoint = {
            let endpoints = self
                .client_endpoints
                .read()
                .map_err(|_| anyhow!("TLS client endpoint lock poisoned"))?;
            if addr.is_ipv6() {
                endpoints.endpoint_v6.clone()
            } else {
                endpoints.endpoint_v4.clone()
            }
        };
        let connect = endpoint
            .connect(addr, "stargate")
            .context("initiate quic connect failed")?;
        let connection = tokio::time::timeout(self.config.connect_timeout, connect)
            .await
            .map_err(|_| anyhow!("quic connect timed out"))?
            .context("quic connect failed")?;
        tokio::time::timeout(
            self.config.connect_timeout,
            self.build_direct_tunnel_connection(connection),
        )
        .await
        .map_err(|_| anyhow!("direct tunnel setup timed out"))?
    }

    pub(crate) fn has_healthy_connection(&self, registration: &RegistrationGeneration) -> bool {
        registration.tunnel_connections().has_healthy_connection()
    }

    pub(crate) fn connection_set_needs_replenishment(
        &self,
        registration: &RegistrationGeneration,
    ) -> bool {
        registration.tunnel_connections().needs_replenishment()
    }

    pub(crate) async fn health_check_rtt(
        &self,
        registration: &RegistrationGeneration,
    ) -> Result<Duration> {
        let inference_server_id = registration.inference_server_id();
        let start = std::time::Instant::now();
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_REQUEST_ID,
            HeaderValue::from_str(&format!("stargate-health-{inference_server_id}"))
                .context("invalid health check request id")?,
        );
        headers.insert(HEADER_MODEL, HeaderValue::from_static("stargate-health"));
        headers.insert(HEADER_INPUT_TOKENS, HeaderValue::from_static("0"));
        let response = self
            .proxy_request_streaming(registration, Method::GET, "/health", headers, Body::empty())
            .await?;
        if !response.status.is_success() {
            bail!("health check returned status {}", response.status);
        }

        let mut body_stream = response.body_stream;
        while body_stream.recv_body().await?.is_some() {}

        Ok(start.elapsed())
    }

    async fn build_direct_tunnel_connection(
        &self,
        connection: Connection,
    ) -> Result<TunnelConnection> {
        match self.config.tunnel_protocol {
            TunnelTransportProtocol::RawQuic => Ok(TunnelConnection::RawQuic(
                RawQuicConnectionHandle::new(connection),
            )),
            TunnelTransportProtocol::Http3 => Ok(TunnelConnection::Http3(
                build_h3_client_connection(connection).await?,
            )),
            TunnelTransportProtocol::WebTransport => Ok(TunnelConnection::WebTransport(
                build_webtransport_client_connection(connection).await?,
            )),
        }
    }

    pub(crate) async fn proxy_request_streaming(
        &self,
        registration: &RegistrationGeneration,
        method: Method,
        path_and_query: &str,
        headers: HeaderMap,
        body: Body,
    ) -> Result<StreamingResponse> {
        let request = self
            .open_streaming_request(registration, method, path_and_query, headers)
            .await?;
        request.send_body_and_recv_response(body).await
    }

    pub(crate) async fn open_streaming_request(
        &self,
        registration: &RegistrationGeneration,
        method: Method,
        path_and_query: &str,
        headers: HeaderMap,
    ) -> Result<OpenStreamingRequest> {
        let _span = info_span!("quic_http_proxy");
        let request =
            OpenTunnelRequest::new(method, path_and_query, headers, self.config.request_timeout);

        let server_id = registration.inference_server_id();
        let connection_set = registration
            .tunnel_connections()
            .connection_set()
            .ok_or_else(|| {
                anyhow!("no connection for exact inference server registration '{server_id}'")
            })?;
        let connection = connection_set
            .choose_healthy()
            .ok_or_else(|| anyhow!("connection to inference server '{server_id}' is closed"))?;

        tokio::time::timeout(
            self.config.request_timeout,
            connection.open_streaming_request(request),
        )
        .await
        .map_err(|_| anyhow!("quic request timed out"))?
    }
}

pub(super) fn parse_quic_addr(target_url: &str) -> Result<SocketAddr> {
    let parsed_url = Url::parse(target_url).context("invalid quic target url")?;
    ensure!(
        parsed_url.scheme() == "quic",
        "target url is not quic scheme"
    );
    let port = parsed_url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("missing port in quic url"))?;
    let ip = parsed_url
        .host_str()
        .and_then(|h| h.parse().ok())
        .ok_or_else(|| anyhow!("quic inference_server_url host must be an IP address"))?;
    Ok(SocketAddr::new(ip, port))
}
