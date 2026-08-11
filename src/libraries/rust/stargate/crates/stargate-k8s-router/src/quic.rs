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
use std::sync::RwLock;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint};
use stargate_forwarding::{
    HostnameMatcher, PeerTarget, RelayEndpointConfig, RelayEndpoints, build_relay_endpoints,
    forward_quic_connection,
};
use tokio::sync::watch;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{info, warn};

use crate::endpoints::{TargetSnapshot, ready_target_for_sni};
use crate::metrics::RouterMetrics;
use crate::tls::{build_router_server_config, build_upstream_client_config};

#[derive(Clone, Debug)]
pub struct QuicRouterConfig {
    pub listen_addr: SocketAddr,
    pub advertised_hostname_template: String,
    pub target_namespace: String,
    pub connect_timeout: Duration,
    pub relay_max_idle_timeout: Duration,
    pub relay_keep_alive_interval: Option<Duration>,
    pub tls_cert_pem: Option<Vec<u8>>,
    pub tls_key_pem: Option<Vec<u8>>,
    pub client_trust_pem: Option<Vec<u8>>,
    pub server_identity_reloader: Option<stargate_tls::ServerIdentityReloader>,
    pub client_trust_reloader: Option<stargate_tls::ClientTrustReloader>,
    pub tls_reload_interval: Duration,
    pub quic_insecure: bool,
}

struct QuicRelay {
    endpoints: RwLock<Arc<RelayEndpoints>>,
    hostname_matcher: Option<HostnameMatcher>,
    connect_timeout: Duration,
}

struct QuicRouterRuntime {
    endpoint: Endpoint,
    bound_addr: SocketAddr,
    relay_config: RelayEndpointConfig,
    relay: Arc<QuicRelay>,
    connection_tasks: TaskTracker,
    server_identity_reloader: Option<stargate_tls::ServerIdentityReloader>,
    client_trust_reloader: Option<stargate_tls::ClientTrustReloader>,
    tls_reload_interval: Duration,
}

impl QuicRouterRuntime {
    fn bind(config: QuicRouterConfig, connection_tasks: TaskTracker) -> Result<Self> {
        let relay_config = RelayEndpointConfig {
            max_idle_timeout: config.relay_max_idle_timeout,
            keep_alive_interval: config.relay_keep_alive_interval,
        };
        let client_config =
            build_client_config(config.client_trust_pem.as_deref(), config.quic_insecure)?;
        let server_config = build_server_config(
            config.tls_cert_pem.as_deref(),
            config.tls_key_pem.as_deref(),
            relay_config,
        )?;
        let endpoint = Endpoint::server(server_config, config.listen_addr)?;
        let bound_addr = endpoint.local_addr()?;
        let relay = Arc::new(QuicRelay {
            endpoints: RwLock::new(Arc::new(build_relay_endpoints(
                relay_config,
                client_config,
            )?)),
            hostname_matcher: HostnameMatcher::new(
                &config.advertised_hostname_template,
                &config.target_namespace,
            ),
            connect_timeout: config.connect_timeout,
        });

        Ok(Self {
            endpoint,
            bound_addr,
            relay_config,
            relay,
            connection_tasks,
            server_identity_reloader: config.server_identity_reloader,
            client_trust_reloader: config.client_trust_reloader,
            tls_reload_interval: config.tls_reload_interval,
        })
    }

    async fn serve(
        self,
        targets: watch::Receiver<TargetSnapshot>,
        metrics: Arc<RouterMetrics>,
        shutdown: CancellationToken,
    ) -> Result<()> {
        info!(
            addr = %self.bound_addr,
            relay_max_idle_timeout_ms = self.relay_config.max_idle_timeout.as_millis(),
            relay_keep_alive_interval_ms =
                self.relay_config.keep_alive_interval.map(|duration| duration.as_millis()),
            "QUIC router listening"
        );
        let mut server_identity_reloader = self.server_identity_reloader;
        let mut client_trust_reloader = self.client_trust_reloader;
        if let Some(reloader) = &server_identity_reloader
            && let Some(validity) =
                stargate_tls::server_identity_effective_validity(reloader.current_identity())?
        {
            metrics.set_tls_certificate_expiry(validity.not_after_unix_seconds);
        }
        let mut reload_changes = stargate_tls::change_detector_for_reloaders(
            server_identity_reloader.as_ref(),
            client_trust_reloader.as_ref(),
            self.tls_reload_interval,
        )?;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    self.endpoint.close(0u32.into(), b"shutdown");
                    return Ok(());
                }
                _ = reload_changes.changed(), if server_identity_reloader.is_some() || client_trust_reloader.is_some() => {
                    if let Some(reloader) = server_identity_reloader.as_mut() {
                        match reloader.load_candidate() {
                            Ok(Some(identity)) => {
                                let activation = (|| -> Result<_> {
                                    let server_config = build_router_server_config(&identity, Vec::new(), self.relay_config)?;
                                    let validity = stargate_tls::server_identity_effective_validity(&identity)?
                                        .context("reloaded server identity has no leaf certificate")?;
                                    Ok((server_config, validity))
                                })();
                                match activation {
                                    Ok((server_config, validity)) => {
                                        self.endpoint.set_server_config(Some(server_config));
                                        reloader.commit(identity);
                                        metrics.set_tls_certificate_expiry(validity.not_after_unix_seconds);
                                        metrics.observe_tls_reload("server_identity", "success");
                                        info!(component = "stargate-k8s-router", material_type = "server_identity", result = "success", not_before_unix_seconds = validity.not_before_unix_seconds, not_after_unix_seconds = validity.not_after_unix_seconds, "TLS material reloaded");
                                    }
                                    Err(error) => {
                                        metrics.observe_tls_reload("server_identity", "rejected");
                                        warn!(component = "stargate-k8s-router", material_type = "server_identity", result = "rejected", %error, "TLS material activation rejected; retaining last-known-good configuration");
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(error) => {
                                metrics.observe_tls_reload("server_identity", "rejected");
                                warn!(component = "stargate-k8s-router", material_type = "server_identity", result = "rejected", %error, "TLS material reload rejected; retaining last-known-good configuration");
                            }
                        }
                    }
                    if let Some(reloader) = client_trust_reloader.as_mut() {
                        match reloader.load_candidate() {
                            Ok(Some(candidate)) => {
                                let activation = (|| -> Result<_> {
                                    let client_config = build_client_config(Some(&candidate), false)?;
                                    let replacement = Arc::new(build_relay_endpoints(self.relay_config, client_config)?);
                                    let mut endpoints = self.relay.endpoints.write().map_err(|_| anyhow::anyhow!("relay endpoint lock poisoned"))?;
                                    Ok(std::mem::replace(&mut *endpoints, replacement))
                                })();
                                match activation {
                                    Ok(previous) => {
                                        reloader.commit(candidate);
                                        previous.close(b"TLS trust configuration replaced");
                                        metrics.observe_tls_reload("client_trust", "success");
                                        info!(component = "stargate-k8s-router", material_type = "client_trust", result = "success", "TLS material reloaded; existing upstream connections closed");
                                    }
                                    Err(error) => {
                                        metrics.observe_tls_reload("client_trust", "rejected");
                                        warn!(component = "stargate-k8s-router", material_type = "client_trust", result = "rejected", %error, "TLS material activation rejected; retaining last-known-good configuration");
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(error) => {
                                metrics.observe_tls_reload("client_trust", "rejected");
                                warn!(component = "stargate-k8s-router", material_type = "client_trust", result = "rejected", %error, "TLS material reload rejected; retaining last-known-good configuration");
                            }
                        }
                    }
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        warn!("QUIC router endpoint stopped accepting");
                        return Ok(());
                    };
                    let relay = self.relay.clone();
                    let targets = targets.clone();
                    let metrics = metrics.clone();
                    let shutdown = shutdown.child_token();
                    self.connection_tasks.spawn(async move {
                        if let Err(error) = dispatch_incoming(
                            incoming,
                            targets,
                            relay,
                            metrics,
                            shutdown,
                        ).await {
                            warn!(%error, "QUIC router connection failed");
                        }
                    });
                }
            }
        }
    }
}

pub async fn serve_quic_router(
    config: QuicRouterConfig,
    targets: watch::Receiver<TargetSnapshot>,
    metrics: Arc<RouterMetrics>,
    shutdown: CancellationToken,
    connection_tasks: TaskTracker,
) -> Result<()> {
    QuicRouterRuntime::bind(config, connection_tasks)?
        .serve(targets, metrics, shutdown)
        .await
}

async fn dispatch_incoming(
    incoming: quinn::Incoming,
    targets: watch::Receiver<TargetSnapshot>,
    relay: Arc<QuicRelay>,
    metrics: Arc<RouterMetrics>,
    shutdown: CancellationToken,
) -> Result<()> {
    let connection = tokio::select! {
        _ = shutdown.cancelled() => return Ok(()),
        connection = incoming => connection.context("accept QUIC connection")?,
    };
    let sni = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|hd| hd.server_name);

    let route = {
        let snapshot = targets.borrow();
        ready_target_for_sni(sni.as_deref(), &snapshot, relay.hostname_matcher.as_ref()).map(
            |(target, server_name)| {
                (
                    target.pod_name.clone(),
                    PeerTarget {
                        dial_addr: target.quic_addr.clone(),
                        server_name: server_name.to_string(),
                    },
                )
            },
        )
    };
    let peer = match route {
        Ok((target_pod, peer)) => {
            metrics.observe_quic_connection("accepted");
            info!(
                %target_pod,
                peer = %peer.dial_addr,
                server_name = %peer.server_name,
                "relaying QUIC connection to stargate target"
            );
            peer
        }
        Err(rejection) => {
            let (metric, reason) = rejection.metric_and_reason();
            metrics.observe_quic_connection(metric);
            connection.close(0u32.into(), reason);
            return Ok(());
        }
    };
    let endpoints = relay
        .endpoints
        .read()
        .map_err(|_| anyhow::anyhow!("relay endpoint lock poisoned"))?
        .clone();
    let relay =
        forward_quic_connection(connection.clone(), &peer, &endpoints, relay.connect_timeout);
    tokio::pin!(relay);
    let relay_result = tokio::select! {
        _ = shutdown.cancelled() => {
            connection.close(0u32.into(), b"router shutdown");
            return Ok(());
        }
        result = &mut relay => result,
    };
    metrics.observe_quic_connection(if relay_result.is_ok() {
        "completed"
    } else {
        "relay_error"
    });
    relay_result
}

fn build_client_config(cert_pem: Option<&[u8]>, insecure: bool) -> Result<ClientConfig> {
    build_upstream_client_config(
        cert_pem,
        insecure,
        Vec::new(),
        "TLS cert required when --quic-insecure is not set",
    )
}

fn build_server_config(
    cert_pem: Option<&[u8]>,
    key_pem: Option<&[u8]>,
    relay_config: RelayEndpointConfig,
) -> Result<quinn::ServerConfig> {
    match (cert_pem, key_pem) {
        (Some(_), None) => anyhow::bail!("router TLS key required when TLS cert is provided"),
        (None, Some(_)) => anyhow::bail!("router TLS cert required when TLS key is provided"),
        _ => {}
    }
    if cert_pem.is_none() && key_pem.is_none() {
        info!("no router TLS cert/key provided, generating self-signed certificate");
    }
    let identity = stargate_tls::ServerTlsIdentity::from_optional_pem(
        cert_pem.map(ToOwned::to_owned),
        key_pem.map(ToOwned::to_owned),
    )?;
    build_router_server_config(&identity, Vec::new(), relay_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hint::black_box;
    use std::time::Instant;

    use crate::endpoints::{PodTarget, SniRouteRejection};
    use crate::perf_tests::assert_twenty_percent_faster;

    fn install_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn cert_and_key() -> (Vec<u8>, Vec<u8>) {
        install_crypto_provider();
        stargate_tls::generate_self_signed_cert().expect("self-signed cert should generate")
    }

    fn cert_and_key_for_names(names: Vec<String>) -> (Vec<u8>, Vec<u8>) {
        install_crypto_provider();
        stargate_tls::generate_self_signed_cert_for_names(names)
            .expect("self-signed cert should generate")
    }

    fn test_config() -> QuicRouterConfig {
        QuicRouterConfig {
            listen_addr: "127.0.0.1:0".parse().expect("valid listen addr"),
            advertised_hostname_template: "{pod_name}.stargate.external".to_string(),
            target_namespace: String::new(),
            connect_timeout: Duration::from_secs(5),
            relay_max_idle_timeout: Duration::from_secs(60),
            relay_keep_alive_interval: Some(Duration::from_secs(5)),
            tls_cert_pem: None,
            tls_key_pem: None,
            client_trust_pem: None,
            server_identity_reloader: None,
            client_trust_reloader: None,
            tls_reload_interval: stargate_tls::DEFAULT_TLS_RELOAD_INTERVAL,
            quic_insecure: true,
        }
    }

    fn snapshot_with_quic_target(pod_name: &str, quic_addr: SocketAddr) -> TargetSnapshot {
        TargetSnapshot::initialized([PodTarget {
            pod_name: pod_name.to_string(),
            grpc_addr: "127.0.0.1:50071".to_string(),
            quic_addr: quic_addr.to_string(),
        }])
    }

    fn synthetic_snapshot(count: usize) -> TargetSnapshot {
        TargetSnapshot::initialized((0..count).map(|index| {
            let pod_name = format!("stargate-{index}");
            PodTarget {
                pod_name,
                grpc_addr: format!("10.0.0.{index}:50071"),
                quic_addr: format!("10.0.0.{index}:50072"),
            }
        }))
    }

    fn matcher(config: &QuicRouterConfig) -> Option<HostnameMatcher> {
        HostnameMatcher::new(
            &config.advertised_hostname_template,
            &config.target_namespace,
        )
    }

    fn assert_ready_route(
        route: Result<(&PodTarget, &str), SniRouteRejection>,
        expected_server_name: &str,
    ) {
        let (target, server_name) = route.expect("route should be ready");
        assert_eq!(target.pod_name, "stargate-1");
        assert_eq!(target.quic_addr, "127.0.0.1:50072");
        assert_eq!(server_name, expected_server_name);
    }

    fn assert_server_config_error(cert_pem: Option<&[u8]>, key_pem: Option<&[u8]>, expected: &str) {
        let error = build_server_config(cert_pem, key_pem, RelayEndpointConfig::default())
            .expect_err("server config should be rejected");
        assert!(error.to_string().contains(expected), "unexpected: {error}");
    }

    fn server_config_from_pem(
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> anyhow::Result<quinn::ServerConfig> {
        let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &*cert_pem).collect::<std::result::Result<_, _>>()?;
        let key =
            rustls_pemfile::private_key(&mut &*key_pem)?.expect("test private key should exist");
        quinn::ServerConfig::with_single_cert(cert_chain, key).map_err(Into::into)
    }

    async fn assert_bidi_relay(
        router_server_config: quinn::ServerConfig,
        target_server_config: quinn::ServerConfig,
        router_client_config: quinn::ClientConfig,
        router_target_client_config: quinn::ClientConfig,
    ) {
        let target_server =
            quinn::Endpoint::server(target_server_config, "127.0.0.1:0".parse().unwrap())
                .expect("target server endpoint");
        let target_addr = target_server.local_addr().expect("target local addr");
        let router_server =
            quinn::Endpoint::server(router_server_config, "127.0.0.1:0".parse().unwrap())
                .expect("router server endpoint");
        let router_addr = router_server.local_addr().expect("router local addr");
        let snapshot = snapshot_with_quic_target("stargate-1", target_addr);
        let (_targets_tx, targets_rx) = watch::channel(snapshot);
        let config = test_config();
        let relay = Arc::new(QuicRelay {
            endpoints: RwLock::new(Arc::new(
                build_relay_endpoints(RelayEndpointConfig::default(), router_target_client_config)
                    .expect("relay endpoints"),
            )),
            hostname_matcher: matcher(&config),
            connect_timeout: config.connect_timeout,
        });
        let metrics = Arc::new(RouterMetrics::new().expect("router metrics"));

        let target_task = tokio::spawn(async move {
            let incoming = target_server.accept().await.expect("target should accept");
            let connection = incoming.await.expect("target connection should finish");
            let (mut send, mut recv) = connection
                .accept_bi()
                .await
                .expect("target should accept relayed bidi stream");
            let body = recv
                .read_to_end(1024)
                .await
                .expect("target should read body");
            assert_eq!(body, b"hello through router");
            send.write_all(b"hello from target")
                .await
                .expect("target should write response");
            send.finish().expect("target should finish response");
            let _ = connection.closed().await;
        });

        let router_task = tokio::spawn(async move {
            let incoming = router_server.accept().await.expect("router should accept");
            dispatch_incoming(
                incoming,
                targets_rx,
                relay,
                metrics,
                CancellationToken::new(),
            )
            .await
            .expect("router should dispatch incoming connection");
        });

        let mut client_endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client endpoint");
        client_endpoint.set_default_client_config(router_client_config);
        let client_connection = client_endpoint
            .connect(router_addr, "stargate-1.stargate.external")
            .expect("connect should start")
            .await
            .expect("connect to router should finish");
        let (mut send, mut recv) = client_connection
            .open_bi()
            .await
            .expect("client should open bidi stream");
        send.write_all(b"hello through router")
            .await
            .expect("client should write body");
        send.finish().expect("client should finish request");
        let response = recv
            .read_to_end(1024)
            .await
            .expect("client should read target response");
        assert_eq!(response, b"hello from target");

        client_connection.close(0u32.into(), b"client complete");
        target_task.await.expect("target task should complete");
        tokio::time::timeout(Duration::from_secs(5), router_task)
            .await
            .expect("router relay should shut down after connections close")
            .expect("router task should not panic");
    }

    #[test]
    fn server_config_rejects_cert_without_key() {
        let (cert, _) = cert_and_key();
        assert_server_config_error(Some(&cert), None, "TLS key required");
    }

    #[test]
    fn server_config_rejects_key_without_cert() {
        let (_, key) = cert_and_key();
        assert_server_config_error(None, Some(&key), "TLS cert required");
    }

    #[test]
    fn quic_server_config_builds_with_provided_cert_key() {
        let (cert, key) = cert_and_key();
        assert!(
            build_server_config(Some(&cert), Some(&key), RelayEndpointConfig::default()).is_ok()
        );
    }

    #[test]
    fn quic_server_config_generates_self_signed_identity_when_tls_absent() {
        assert!(build_server_config(None, None, RelayEndpointConfig::default()).is_ok());
    }

    #[test]
    fn quic_server_config_rejects_invalid_cert_pem() {
        let (_, key) = cert_and_key();
        assert_server_config_error(Some(b"not a cert"), Some(&key), "no certificate found");
    }

    #[test]
    fn quic_server_config_rejects_invalid_key_pem() {
        let (cert, _) = cert_and_key();
        assert_server_config_error(Some(&cert), Some(b"not a key"), "no private key found");
    }

    #[test]
    fn client_config_requires_cert_in_secure_mode() {
        let error =
            build_client_config(None, false).expect_err("secure client config should require cert");

        assert!(
            error
                .to_string()
                .contains("TLS cert required when --quic-insecure is not set")
        );
    }

    #[test]
    fn route_for_sni_returns_ready_peer_for_matching_target() {
        let target_addr: SocketAddr = "127.0.0.1:50072".parse().expect("valid target addr");
        let snapshot = snapshot_with_quic_target("stargate-1", target_addr);
        let config = test_config();
        assert_ready_route(
            ready_target_for_sni(
                Some("stargate-1.stargate.external"),
                &snapshot,
                matcher(&config).as_ref(),
            ),
            "stargate-1.stargate.external",
        );
    }

    #[test]
    fn route_for_sni_rejects_missing_unknown_and_unready_targets() {
        let target_addr: SocketAddr = "127.0.0.1:50072".parse().expect("valid target addr");
        let snapshot = snapshot_with_quic_target("stargate-1", target_addr);
        let config = test_config();
        let matcher = matcher(&config);

        assert_eq!(
            ready_target_for_sni(None, &snapshot, matcher.as_ref()),
            Err(SniRouteRejection::MissingSni)
        );
        assert_eq!(
            ready_target_for_sni(
                Some("stargate-1.other.example"),
                &snapshot,
                matcher.as_ref(),
            ),
            Err(SniRouteRejection::UnknownSni)
        );
        assert_eq!(
            ready_target_for_sni(
                Some("stargate-2.stargate.external"),
                &snapshot,
                matcher.as_ref(),
            ),
            Err(SniRouteRejection::TargetUnavailable)
        );
    }

    #[test]
    fn route_for_sni_matches_namespace_hostname_template() {
        let target_addr: SocketAddr = "127.0.0.1:50072".parse().expect("valid target addr");
        let snapshot = snapshot_with_quic_target("stargate-1", target_addr);
        let mut config = test_config();
        config.advertised_hostname_template =
            "{pod_name}.{namespace}.stargate.external".to_string();
        config.target_namespace = "prod".to_string();
        let matcher = matcher(&config);

        assert_ready_route(
            ready_target_for_sni(
                Some("stargate-1.prod.stargate.external"),
                &snapshot,
                matcher.as_ref(),
            ),
            "stargate-1.prod.stargate.external",
        );
    }

    #[test]
    #[ignore = "performance benchmark; run with --ignored --nocapture"]
    fn bench_quic_sni_route_resolution() {
        const BASELINE_NS_PER_OP: f64 = 265.32;

        let snapshot = synthetic_snapshot(128);
        let config = test_config();
        let matcher = matcher(&config);
        let iterations = 1_000_000usize;
        let started = Instant::now();
        let mut checksum = 0usize;

        for _ in 0..iterations {
            match ready_target_for_sni(
                black_box(Some("stargate-64.stargate.external")),
                black_box(&snapshot),
                black_box(matcher.as_ref()),
            ) {
                Ok((target, server_name)) => {
                    checksum = checksum
                        .wrapping_add(target.pod_name.len())
                        .wrapping_add(target.quic_addr.len())
                        .wrapping_add(server_name.len());
                }
                route => panic!("unexpected route: {route:?}"),
            }
        }

        let elapsed = started.elapsed();
        let ns_per_op = elapsed.as_nanos() as f64 / iterations as f64;
        eprintln!(
            "bench_quic_sni_route_resolution: iterations={iterations} elapsed={elapsed:?} ns_per_op={ns_per_op:.2} checksum={checksum}"
        );
        assert!(checksum > 0);
        assert_twenty_percent_faster(
            "bench_quic_sni_route_resolution",
            BASELINE_NS_PER_OP,
            ns_per_op,
        );
    }

    #[tokio::test]
    async fn quic_router_relays_raw_quic_bidi_streams_by_sni() {
        let (router_cert, router_key) = cert_and_key();
        let (target_cert, target_key) = cert_and_key();
        assert_bidi_relay(
            server_config_from_pem(&router_cert, &router_key).expect("router server config"),
            server_config_from_pem(&target_cert, &target_key).expect("target server config"),
            build_client_config(None, true).expect("insecure client config"),
            build_client_config(None, true).expect("insecure relay client config"),
        )
        .await;
    }

    #[tokio::test]
    async fn quic_router_cancellation_stops_after_startup() {
        install_crypto_provider();
        let (_targets_tx, targets_rx) = watch::channel(TargetSnapshot::default());
        let metrics = Arc::new(RouterMetrics::new().expect("router metrics"));
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            serve_quic_router(
                test_config(),
                targets_rx,
                metrics,
                shutdown,
                TaskTracker::new(),
            ),
        )
        .await
        .expect("router should observe cancellation");

        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_router_shutdown_cancels_active_relay_and_drains_tracker() {
        install_crypto_provider();
        let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("black-hole upstream socket should bind");
        let mut config = test_config();
        config.connect_timeout = Duration::from_secs(30);
        let snapshot = snapshot_with_quic_target(
            "stargate-1",
            upstream_socket
                .local_addr()
                .expect("black-hole upstream address should be readable"),
        );
        let (_targets_tx, targets_rx) = watch::channel(snapshot);
        let metrics = Arc::new(RouterMetrics::new().expect("router metrics"));
        let shutdown = CancellationToken::new();
        let connection_tasks = TaskTracker::new();
        let runtime = QuicRouterRuntime::bind(config, connection_tasks.clone())
            .expect("router listener should bind");
        let router_addr = runtime.bound_addr;
        let router_task = tokio::spawn(runtime.serve(targets_rx, metrics, shutdown.clone()));

        let mut client_endpoint =
            Endpoint::client("127.0.0.1:0".parse().expect("valid client bind"))
                .expect("client endpoint should bind");
        client_endpoint.set_default_client_config(
            build_client_config(None, true).expect("insecure client config should build"),
        );
        let client_connection = client_endpoint
            .connect(router_addr, "stargate-1.stargate.external")
            .expect("start router connection")
            .await
            .expect("router connection should establish");

        let mut datagram = [0_u8; 2048];
        tokio::time::timeout(
            Duration::from_secs(1),
            upstream_socket.recv_from(&mut datagram),
        )
        .await
        .expect("active relay should attempt the upstream QUIC handshake")
        .expect("black-hole upstream socket should receive a QUIC datagram");

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), router_task)
            .await
            .expect("router root should stop after cancellation")
            .expect("router task should not panic")
            .expect("router root should return cleanly");
        connection_tasks.close();
        tokio::time::timeout(Duration::from_secs(1), connection_tasks.wait())
            .await
            .expect("active relay task should drain after cancellation");
        client_connection.close(0u32.into(), b"test complete");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_router_reloads_server_identity_for_new_handshakes() {
        install_crypto_provider();
        let root = tempfile::tempdir().expect("TLS temp directory");
        let cert_path = root.path().join("tls.crt");
        let key_path = root.path().join("tls.key");
        let server_name = "stargate-1.stargate.external";
        let (first_cert, first_key) = cert_and_key_for_names(vec![server_name.to_string()]);
        let (second_cert, second_key) = cert_and_key_for_names(vec![server_name.to_string()]);
        std::fs::write(&cert_path, &first_cert).expect("write initial certificate");
        std::fs::write(&key_path, &first_key).expect("write initial key");

        let mut config = test_config();
        config.tls_cert_pem = Some(first_cert.clone());
        config.tls_key_pem = Some(first_key);
        config.server_identity_reloader = Some(
            stargate_tls::ServerIdentityReloader::load(cert_path.clone(), key_path.clone())
                .expect("load initial server identity"),
        );
        config.tls_reload_interval = Duration::from_millis(10);
        let upstream_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("black-hole upstream socket should bind");
        let snapshot = snapshot_with_quic_target(
            "stargate-1",
            upstream_socket.local_addr().expect("upstream address"),
        );
        let (_targets_tx, targets_rx) = watch::channel(snapshot);
        let metrics = Arc::new(RouterMetrics::new().expect("router metrics"));
        let shutdown = CancellationToken::new();
        let connection_tasks = TaskTracker::new();
        let runtime = QuicRouterRuntime::bind(config, connection_tasks.clone())
            .expect("router listener should bind");
        let router_addr = runtime.bound_addr;
        let router_task = tokio::spawn(runtime.serve(targets_rx, metrics, shutdown.clone()));

        async fn connects(addr: SocketAddr, server_name: &str, trust_pem: &[u8]) -> bool {
            let Ok(mut endpoint) = Endpoint::client("127.0.0.1:0".parse().unwrap()) else {
                return false;
            };
            let Ok(client_config) =
                stargate_tls::build_trusted_quic_client_config_with_alpn(trust_pem, Vec::new())
            else {
                return false;
            };
            endpoint.set_default_client_config(client_config);
            let Ok(connecting) = endpoint.connect(addr, server_name) else {
                return false;
            };
            connecting.await.is_ok()
        }

        assert!(connects(router_addr, server_name, &first_cert).await);
        std::fs::write(&key_path, second_key).expect("write replacement key");
        std::fs::write(&cert_path, &second_cert).expect("write replacement certificate");
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if connects(router_addr, server_name, &second_cert).await {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("replacement identity should become active");
        assert!(!connects(router_addr, server_name, &first_cert).await);

        shutdown.cancel();
        router_task
            .await
            .expect("router task should not panic")
            .unwrap();
        connection_tasks.close();
        connection_tasks.wait().await;
    }

    #[tokio::test]
    async fn quic_router_secure_relay_preserves_target_sni() {
        let names = vec!["stargate-1.stargate.external".to_string()];
        let (router_cert, router_key) = cert_and_key_for_names(names.clone());
        let (target_cert, target_key) = cert_and_key_for_names(names);
        assert_bidi_relay(
            server_config_from_pem(&router_cert, &router_key).expect("router server config"),
            server_config_from_pem(&target_cert, &target_key).expect("target server config"),
            build_client_config(None, true).expect("insecure client config"),
            build_client_config(Some(&target_cert), false).expect("secure relay client config"),
        )
        .await;
    }
}
