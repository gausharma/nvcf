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

use anyhow::Result;
use prometheus::{Encoder, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

#[derive(Clone)]
pub struct RouterMetrics {
    registry: Registry,
    quic_connections_total: IntCounterVec,
    webtransport_sessions_total: IntCounterVec,
    tls_reloads_total: IntCounterVec,
    tls_certificate_expiry_seconds: IntGaugeVec,
    tls_identity_not_after: Arc<AtomicI64>,
}

impl RouterMetrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();
        let quic_connections_total = IntCounterVec::new(
            Opts::new(
                "stargate_k8s_router_quic_connections_total",
                "QUIC reverse-tunnel router connections by outcome.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(quic_connections_total.clone()))?;
        let webtransport_sessions_total = IntCounterVec::new(
            Opts::new(
                "stargate_k8s_router_webtransport_sessions_total",
                "WebTransport reverse-tunnel router sessions by outcome.",
            ),
            &["outcome"],
        )?;
        registry.register(Box::new(webtransport_sessions_total.clone()))?;
        let tls_reloads_total = IntCounterVec::new(
            Opts::new(
                "stargate_k8s_router_tls_reloads_total",
                "TLS material reload attempts by material type and result.",
            ),
            &["material_type", "result"],
        )?;
        registry.register(Box::new(tls_reloads_total.clone()))?;
        for material_type in ["server_identity", "client_trust"] {
            for result in ["success", "rejected"] {
                tls_reloads_total
                    .with_label_values(&[material_type, result])
                    .inc_by(0);
            }
        }
        let tls_certificate_expiry_seconds = IntGaugeVec::new(
            Opts::new(
                "stargate_k8s_router_tls_certificate_expiry_seconds",
                "Unix timestamp when the active TLS certificate expires.",
            ),
            &["material_type"],
        )?;
        registry.register(Box::new(tls_certificate_expiry_seconds.clone()))?;
        tls_certificate_expiry_seconds
            .with_label_values(&["server_identity"])
            .set(0);

        Ok(Self {
            registry,
            quic_connections_total,
            webtransport_sessions_total,
            tls_reloads_total,
            tls_certificate_expiry_seconds,
            tls_identity_not_after: Arc::new(AtomicI64::new(i64::MAX)),
        })
    }

    pub fn observe_quic_connection(&self, outcome: &str) {
        self.quic_connections_total
            .with_label_values(&[outcome])
            .inc();
    }

    pub fn observe_webtransport_session(&self, outcome: &str) {
        self.webtransport_sessions_total
            .with_label_values(&[outcome])
            .inc();
    }

    pub fn observe_tls_reload(&self, material_type: &str, result: &str) {
        self.tls_reloads_total
            .with_label_values(&[material_type, result])
            .inc();
    }

    pub fn set_tls_certificate_expiry(&self, unix_seconds: i64) {
        self.tls_certificate_expiry_seconds
            .with_label_values(&["server_identity"])
            .set(unix_seconds);
        self.tls_identity_not_after
            .store(unix_seconds, Ordering::Release);
    }

    pub fn tls_identity_is_ready(&self) -> bool {
        let expiry = self.tls_identity_not_after.load(Ordering::Acquire);
        expiry == i64::MAX
            || (expiry >= 0
                && std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .is_ok_and(|now| now.as_secs() <= expiry as u64))
    }

    pub fn gather(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        encoder.encode(&self.registry.gather(), &mut buffer)?;
        String::from_utf8(buffer).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_exports_quic_connection_outcomes() {
        let metrics = RouterMetrics::new().expect("metrics should initialize");
        metrics.observe_quic_connection("accepted");
        metrics.observe_quic_connection("accepted");
        metrics.observe_quic_connection("unknown_sni");

        let body = metrics.gather().expect("metrics should encode");

        assert!(
            body.contains(r#"stargate_k8s_router_quic_connections_total{outcome="accepted"} 2"#)
        );
        assert!(
            body.contains(r#"stargate_k8s_router_quic_connections_total{outcome="unknown_sni"} 1"#)
        );
    }

    #[test]
    fn metrics_exports_webtransport_session_outcomes() {
        let metrics = RouterMetrics::new().expect("metrics should initialize");
        metrics.observe_webtransport_session("accepted");
        metrics.observe_webtransport_session("completed");

        let body = metrics.gather().expect("metrics should encode");

        assert!(
            body.contains(
                r#"stargate_k8s_router_webtransport_sessions_total{outcome="accepted"} 1"#
            )
        );
        assert!(
            body.contains(
                r#"stargate_k8s_router_webtransport_sessions_total{outcome="completed"} 1"#
            )
        );
    }

    #[test]
    fn tls_reload_metrics_are_preinitialized_and_bounded() {
        let metrics = RouterMetrics::new().expect("metrics should initialize");
        metrics.observe_tls_reload("server_identity", "success");
        metrics.set_tls_certificate_expiry(1_800_000_000);
        let body = metrics.gather().expect("metrics should encode");

        assert!(body.contains(r#"stargate_k8s_router_tls_reloads_total{material_type="server_identity",result="success"} 1"#));
        assert!(body.contains(r#"stargate_k8s_router_tls_reloads_total{material_type="client_trust",result="rejected"} 0"#));
        assert!(body.contains(r#"stargate_k8s_router_tls_certificate_expiry_seconds{material_type="server_identity"} 1800000000"#));
    }
}
