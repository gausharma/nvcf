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

use std::borrow::Cow;
use std::fmt;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use quinn::{ClientConfig, ServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

const MAX_TLS_MATERIAL_BYTES: u64 = 1024 * 1024;

/// Default polling interval for projected TLS material, below the 30-second reload contract.
pub const DEFAULT_TLS_RELOAD_INTERVAL: Duration = Duration::from_secs(10);

/// Generates a PEM self-signed certificate and key with SANs for `localhost` and `stargate`.
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    generate_self_signed_cert_for_names(vec!["localhost".to_string(), "stargate".to_string()])
}

/// Generates a self-signed certificate and private key for the supplied DNS names.
pub fn generate_self_signed_cert_for_names(names: Vec<String>) -> Result<(Vec<u8>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(names)
        .context("failed to generate self-signed certificate")?;
    let cert_pem = cert.cert.pem().into_bytes();
    let key_pem = cert.key_pair.serialize_pem().into_bytes();
    Ok((cert_pem, key_pem))
}

pub type ServerTlsPemPair<'a> = (Cow<'a, [u8]>, Cow<'a, [u8]>);

/// Prefers IPv4 dial addresses, preserving each family's resolver order and IPv6 fallback.
pub fn ordered_dial_candidates(
    resolved_addrs: impl IntoIterator<Item = SocketAddr>,
) -> Vec<SocketAddr> {
    let (mut ipv4, ipv6): (Vec<_>, Vec<_>) =
        resolved_addrs.into_iter().partition(SocketAddr::is_ipv4);
    ipv4.extend(ipv6);
    ipv4
}

/// Returns an ephemeral unspecified local address compatible with `remote_addr`.
pub fn quic_client_bind_addr(remote_addr: SocketAddr) -> SocketAddr {
    match remote_addr {
        SocketAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        SocketAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    }
}

/// TLS identity used by QUIC tunnel servers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ServerTlsIdentity {
    #[default]
    SelfSigned,
    Provided {
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
    },
}

/// Validity window for the leaf certificate in a provided server identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateValidity {
    pub not_before_unix_seconds: i64,
    pub not_after_unix_seconds: i64,
}

impl ServerTlsIdentity {
    /// Builds a server identity from optional certificate/key PEM inputs.
    pub fn from_optional_pem(cert_pem: Option<Vec<u8>>, key_pem: Option<Vec<u8>>) -> Result<Self> {
        match (cert_pem, key_pem) {
            (Some(cert_pem), Some(key_pem)) => Ok(Self::Provided { cert_pem, key_pem }),
            (None, None) => Ok(Self::SelfSigned),
            (Some(_), None) => bail!("TLS key PEM is required when TLS cert PEM is provided"),
            (None, Some(_)) => bail!("TLS cert PEM is required when TLS key PEM is provided"),
        }
    }

    /// Returns the PEM pair to parse when building a server config.
    pub fn pem_pair(&self) -> Result<ServerTlsPemPair<'_>> {
        match self {
            Self::SelfSigned => generate_self_signed_cert()
                .map(|(cert_pem, key_pem)| (Cow::Owned(cert_pem), Cow::Owned(key_pem))),
            Self::Provided { cert_pem, key_pem } => Ok((cert_pem.into(), key_pem.into())),
        }
    }
}

/// Reloads a complete certificate and private-key pair while retaining the last valid identity.
#[derive(Clone)]
pub struct ServerIdentityReloader {
    cert_path: PathBuf,
    key_path: PathBuf,
    current: ServerTlsIdentity,
    last_rejected_fingerprint: Option<u64>,
}

impl fmt::Debug for ServerIdentityReloader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerIdentityReloader")
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("has_active_identity", &true)
            .field(
                "has_suppressed_rejection",
                &self.last_rejected_fingerprint.is_some(),
            )
            .finish()
    }
}

/// Provides the most recently validated client trust bundle to connection owners.
#[derive(Clone, Debug)]
pub struct ClientTrustProvider {
    current: tokio::sync::watch::Sender<Vec<u8>>,
}

impl ClientTrustProvider {
    /// Returns a snapshot of the active trust bundle PEM.
    pub fn current_pem(&self) -> Vec<u8> {
        self.current.borrow().clone()
    }

    /// Subscribes to valid trust-bundle replacements.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Vec<u8>> {
        self.current.subscribe()
    }
}

/// Reloads a trust bundle while retaining and publishing the last valid generation.
#[derive(Clone, Debug)]
pub struct ClientTrustReloader {
    trust_path: PathBuf,
    current: Vec<u8>,
    updates: tokio::sync::watch::Sender<Vec<u8>>,
    last_rejected_fingerprint: Option<u64>,
}

impl ClientTrustReloader {
    /// Loads and validates the initial trust bundle from `trust_path`.
    pub fn load(trust_path: PathBuf) -> Result<(Self, ClientTrustProvider)> {
        let current = read_trust_bundle(&trust_path)?;
        let (updates, _) = tokio::sync::watch::channel(current.clone());
        let provider = ClientTrustProvider {
            current: updates.clone(),
        };
        Ok((
            Self {
                trust_path,
                current,
                updates,
                last_rejected_fingerprint: None,
            },
            provider,
        ))
    }

    /// Validates and publishes a changed trust bundle.
    pub fn reload_if_changed(&mut self) -> Result<bool> {
        let Some(candidate) = self.load_candidate()? else {
            return Ok(false);
        };
        self.commit(candidate);
        Ok(true)
    }

    /// Loads a changed, validated trust bundle without changing active state.
    pub fn load_candidate(&mut self) -> Result<Option<Vec<u8>>> {
        let candidate = match read_trust_bundle(&self.trust_path) {
            Ok(candidate) => {
                self.last_rejected_fingerprint = None;
                candidate
            }
            Err(error) => {
                let fingerprint = rejection_fingerprint(&[&self.trust_path]);
                if self.last_rejected_fingerprint == Some(fingerprint) {
                    return Ok(None);
                }
                self.last_rejected_fingerprint = Some(fingerprint);
                return Err(error);
            }
        };
        Ok((candidate != self.current).then_some(candidate))
    }

    /// Publishes a candidate after the connection owner activates it.
    pub fn commit(&mut self, candidate: Vec<u8>) {
        self.current = candidate.clone();
        self.updates.send_replace(candidate);
    }

    /// Returns a snapshot of the active last-known-good trust bundle.
    pub fn current_pem(&self) -> &[u8] {
        &self.current
    }
}

impl ServerIdentityReloader {
    /// Loads and validates the initial identity from `cert_path` and `key_path`.
    pub fn load(cert_path: PathBuf, key_path: PathBuf) -> Result<Self> {
        let current = read_server_identity(&cert_path, &key_path)?;
        Ok(Self {
            cert_path,
            key_path,
            current,
            last_rejected_fingerprint: None,
        })
    }

    /// Returns the active last-known-good identity.
    pub fn current_identity(&self) -> &ServerTlsIdentity {
        &self.current
    }

    /// Loads a complete replacement generation and returns it only when its contents changed.
    pub fn reload_if_changed(&mut self) -> Result<Option<ServerTlsIdentity>> {
        let Some(candidate) = self.load_candidate()? else {
            return Ok(None);
        };
        self.commit(candidate.clone());
        Ok(Some(candidate))
    }

    /// Loads a changed, validated identity without changing active state.
    pub fn load_candidate(&mut self) -> Result<Option<ServerTlsIdentity>> {
        let candidate = match read_server_identity(&self.cert_path, &self.key_path) {
            Ok(candidate) => {
                self.last_rejected_fingerprint = None;
                candidate
            }
            Err(error) => {
                let fingerprint = rejection_fingerprint(&[&self.cert_path, &self.key_path]);
                if self.last_rejected_fingerprint == Some(fingerprint) {
                    return Ok(None);
                }
                self.last_rejected_fingerprint = Some(fingerprint);
                return Err(error);
            }
        };
        Ok((candidate != self.current).then_some(candidate))
    }

    /// Records a candidate after the connection owner activates it.
    pub fn commit(&mut self, candidate: ServerTlsIdentity) {
        self.current = candidate;
    }

    /// Installs a valid changed identity for new QUIC handshakes.
    pub fn reload_quic_server_config_if_changed(
        &mut self,
        endpoint: &quinn::Endpoint,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Result<bool> {
        let Some(identity) = self.load_candidate()? else {
            return Ok(false);
        };
        let server_config = build_quic_server_config(&identity, alpn_protocols)?;
        endpoint.set_server_config(Some(server_config));
        self.commit(identity);
        Ok(true)
    }
}

fn read_server_identity(cert_path: &Path, key_path: &Path) -> Result<ServerTlsIdentity> {
    let cert_resolved = cert_path.canonicalize().with_context(|| {
        format!(
            "failed to resolve TLS certificate path {}",
            cert_path.display()
        )
    })?;
    let key_resolved = key_path.canonicalize().with_context(|| {
        format!(
            "failed to resolve TLS private key path {}",
            key_path.display()
        )
    })?;
    if cert_path.parent() == key_path.parent() && cert_resolved.parent() != key_resolved.parent() {
        bail!("TLS certificate and private key resolve to different projected generations");
    }

    let cert_pem = read_bounded_file(&cert_resolved, "TLS certificate")?;
    let key_pem = read_bounded_file(&key_resolved, "TLS private key")?;
    let identity = ServerTlsIdentity::from_optional_pem(Some(cert_pem), Some(key_pem))?;
    build_quic_server_config(&identity, Vec::new()).context("invalid TLS server identity")?;
    validate_server_identity_time(&identity)?;
    Ok(identity)
}

/// Parses and returns the validity window of a provided server identity.
pub fn server_identity_validity(
    identity: &ServerTlsIdentity,
) -> Result<Option<CertificateValidity>> {
    let ServerTlsIdentity::Provided { cert_pem, .. } = identity else {
        return Ok(None);
    };
    let leaf = rustls_pemfile::certs(&mut &**cert_pem)
        .next()
        .transpose()
        .context("failed to parse TLS leaf certificate PEM")?
        .context("no certificate found in TLS PEM")?;
    parse_certificate_validity(leaf.as_ref()).map(Some)
}

/// Returns the validity window shared by every certificate in the served chain.
pub fn server_identity_effective_validity(
    identity: &ServerTlsIdentity,
) -> Result<Option<CertificateValidity>> {
    let ServerTlsIdentity::Provided { cert_pem, .. } = identity else {
        return Ok(None);
    };
    let mut effective: Option<CertificateValidity> = None;
    for certificate in rustls_pemfile::certs(&mut &**cert_pem) {
        let certificate = certificate.context("failed to parse TLS certificate chain PEM")?;
        let validity = parse_certificate_validity(certificate.as_ref())?;
        effective = Some(match effective {
            Some(current) => CertificateValidity {
                not_before_unix_seconds: current
                    .not_before_unix_seconds
                    .max(validity.not_before_unix_seconds),
                not_after_unix_seconds: current
                    .not_after_unix_seconds
                    .min(validity.not_after_unix_seconds),
            },
            None => validity,
        });
    }
    effective
        .context("no certificate found in TLS PEM")
        .map(Some)
}

/// Rejects a provided server identity outside its certificate validity window.
pub fn validate_server_identity_time(identity: &ServerTlsIdentity) -> Result<()> {
    let ServerTlsIdentity::Provided { cert_pem, .. } = identity else {
        return Ok(());
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before the Unix epoch")?
        .as_secs() as i64;
    let mut certificate_count = 0usize;
    for (index, certificate) in rustls_pemfile::certs(&mut &**cert_pem).enumerate() {
        let certificate = certificate.context("failed to parse TLS certificate chain PEM")?;
        let validity = parse_certificate_validity(certificate.as_ref())?;
        ensure!(
            now >= validity.not_before_unix_seconds,
            "TLS certificate {index} is not yet valid"
        );
        ensure!(
            now <= validity.not_after_unix_seconds,
            "TLS certificate {index} is expired"
        );
        certificate_count += 1;
    }
    ensure!(certificate_count > 0, "no certificate found in TLS PEM");
    Ok(())
}

struct DerReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn peek_tag(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn read(&mut self, expected_tag: u8) -> Result<&'a [u8]> {
        ensure!(
            self.input.get(self.offset).copied() == Some(expected_tag),
            "unexpected DER tag while parsing certificate validity"
        );
        self.offset += 1;
        let first_length = *self
            .input
            .get(self.offset)
            .context("missing DER length while parsing certificate validity")?;
        self.offset += 1;
        let length = if first_length & 0x80 == 0 {
            first_length as usize
        } else {
            let length_bytes = (first_length & 0x7f) as usize;
            ensure!(
                (1..=4).contains(&length_bytes),
                "unsupported DER length while parsing certificate validity"
            );
            ensure!(
                self.offset + length_bytes <= self.input.len(),
                "truncated DER length while parsing certificate validity"
            );
            let mut length = 0usize;
            for byte in &self.input[self.offset..self.offset + length_bytes] {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(*byte as usize))
                    .context("DER length overflow while parsing certificate validity")?;
            }
            self.offset += length_bytes;
            length
        };
        let end = self
            .offset
            .checked_add(length)
            .context("DER offset overflow while parsing certificate validity")?;
        ensure!(
            end <= self.input.len(),
            "truncated DER value while parsing certificate validity"
        );
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }
}

fn parse_certificate_validity(cert_der: &[u8]) -> Result<CertificateValidity> {
    let mut certificate = DerReader::new(cert_der);
    let certificate_sequence = certificate.read(0x30)?;
    let mut certificate = DerReader::new(certificate_sequence);
    let tbs_certificate = certificate.read(0x30)?;
    let mut tbs = DerReader::new(tbs_certificate);
    if tbs.peek_tag() == Some(0xa0) {
        tbs.read(0xa0)?;
    }
    tbs.read(0x02)?;
    tbs.read(0x30)?;
    tbs.read(0x30)?;
    let validity = tbs.read(0x30)?;
    let mut validity = DerReader::new(validity);
    let not_before = read_der_time(&mut validity)?;
    let not_after = read_der_time(&mut validity)?;
    ensure!(
        not_before <= not_after,
        "TLS leaf certificate has an invalid validity window"
    );
    Ok(CertificateValidity {
        not_before_unix_seconds: not_before,
        not_after_unix_seconds: not_after,
    })
}

fn read_der_time(reader: &mut DerReader<'_>) -> Result<i64> {
    let tag = reader
        .peek_tag()
        .context("missing certificate validity time")?;
    let value = reader.read(tag)?;
    let (year, rest) = match tag {
        0x17 => {
            ensure!(value.len() == 13, "invalid X.509 UTC time");
            let year = parse_decimal(&value[0..2])?;
            ((if year >= 50 { 1900 } else { 2000 }) + year, &value[2..])
        }
        0x18 => {
            ensure!(value.len() == 15, "invalid X.509 generalized time");
            (parse_decimal(&value[0..4])?, &value[4..])
        }
        _ => bail!("invalid X.509 certificate validity time tag"),
    };
    ensure!(rest.last() == Some(&b'Z'), "X.509 validity time is not UTC");
    let month = parse_decimal(&rest[0..2])?;
    let day = parse_decimal(&rest[2..4])?;
    let hour = parse_decimal(&rest[4..6])?;
    let minute = parse_decimal(&rest[6..8])?;
    let second = parse_decimal(&rest[8..10])?;
    ensure!((1..=12).contains(&month), "invalid X.509 validity month");
    ensure!(
        (1..=days_in_month(year, month)).contains(&day),
        "invalid X.509 validity day"
    );
    ensure!(
        hour < 24 && minute < 60 && second < 60,
        "invalid X.509 validity time"
    );
    Ok(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn parse_decimal(input: &[u8]) -> Result<i64> {
    ensure!(
        input.iter().all(u8::is_ascii_digit),
        "invalid decimal in X.509 validity time"
    );
    input.iter().try_fold(0i64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add((byte - b'0') as i64))
            .context("X.509 validity time overflow")
    })
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn read_bounded_file(path: &Path, material: &str) -> Result<Vec<u8>> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open {material} file {}", path.display()))?;
    let mut contents = Vec::new();
    file.take(MAX_TLS_MATERIAL_BYTES + 1)
        .read_to_end(&mut contents)
        .with_context(|| format!("failed to read {material} file {}", path.display()))?;
    ensure!(
        contents.len() as u64 <= MAX_TLS_MATERIAL_BYTES,
        "{material} exceeds {MAX_TLS_MATERIAL_BYTES} bytes"
    );
    Ok(contents)
}

fn rejection_fingerprint(paths: &[&PathBuf]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for path in paths {
        path.hash(&mut hasher);
        match path.canonicalize() {
            Ok(resolved) => {
                resolved.hash(&mut hasher);
                match read_bounded_file(&resolved, "TLS material") {
                    Ok(contents) => contents.hash(&mut hasher),
                    Err(error) => error.to_string().hash(&mut hasher),
                }
            }
            Err(error) => error.to_string().hash(&mut hasher),
        }
    }
    hasher.finish()
}

fn read_trust_bundle(path: &Path) -> Result<Vec<u8>> {
    let resolved = path
        .canonicalize()
        .with_context(|| format!("failed to resolve TLS trust path {}", path.display()))?;
    let trust_pem = read_bounded_file(&resolved, "TLS trust bundle")?;
    build_trusted_quic_client_config_with_alpn(&trust_pem, Vec::new())
        .context("invalid TLS trust bundle")?;
    Ok(trust_pem)
}

/// Polls projected certificate and key files and updates new QUIC handshakes in place.
pub async fn run_quic_server_identity_reloader(
    mut reloader: ServerIdentityReloader,
    endpoint: quinn::Endpoint,
    alpn_protocols: Vec<Vec<u8>>,
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
                match reloader.reload_quic_server_config_if_changed(
                    &endpoint,
                    alpn_protocols.clone(),
                ) {
                    Ok(true) => tracing::info!(
                        material_type = "server_identity",
                        result = "success",
                        "TLS material reloaded"
                    ),
                    Ok(false) => {}
                    Err(error) => tracing::warn!(
                        material_type = "server_identity",
                        result = "rejected",
                        error = %error,
                        "TLS material reload rejected; retaining last-known-good configuration"
                    ),
                }
            }
        }
    }
}

/// Polls a projected trust-bundle file and publishes valid replacements.
pub async fn run_client_trust_reloader(
    mut reloader: ClientTrustReloader,
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
                match reloader.reload_if_changed() {
                    Ok(true) => tracing::info!(
                        material_type = "client_trust",
                        result = "success",
                        "TLS material reloaded"
                    ),
                    Ok(false) => {}
                    Err(error) => tracing::warn!(
                        material_type = "client_trust",
                        result = "rejected",
                        error = %error,
                        "TLS material reload rejected; retaining last-known-good configuration"
                    ),
                }
            }
        }
    }
}

/// Builds a QUIC client config that skips server certificate verification.
pub fn build_insecure_quic_client_config() -> Result<ClientConfig> {
    build_insecure_quic_client_config_with_alpn(Vec::new())
}

/// Builds a QUIC client config that skips verification and advertises the supplied ALPN list.
pub fn build_insecure_quic_client_config_with_alpn(
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ClientConfig> {
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
        .with_no_client_auth();
    tls_config.alpn_protocols = alpn_protocols;
    quic_client_config(tls_config)
}

/// Selects verified or insecure QUIC client TLS from the supplied trust policy.
pub fn build_quic_client_config(
    cert_pem: Option<&[u8]>,
    insecure: bool,
    alpn_protocols: Vec<Vec<u8>>,
    missing_trust_error: &'static str,
) -> Result<ClientConfig> {
    if insecure {
        return build_insecure_quic_client_config_with_alpn(alpn_protocols);
    }
    build_trusted_quic_client_config_with_alpn(
        cert_pem.context(missing_trust_error)?,
        alpn_protocols,
    )
}

/// Builds a QUIC client config using the supplied PEM trust anchor and ALPN list.
pub fn build_trusted_quic_client_config_with_alpn(
    cert_pem: &[u8],
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &*cert_pem) {
        roots
            .add(cert.context("failed to parse cert PEM")?)
            .context("failed to add cert to root store")?;
    }
    ensure!(
        !roots.is_empty(),
        "TLS trust bundle contains no certificates"
    );
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = alpn_protocols;
    quic_client_config(tls_config)
}

/// Builds a QUIC server config from one identity and ALPN policy.
pub fn build_quic_server_config(
    identity: &ServerTlsIdentity,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ServerConfig> {
    let (cert_pem, key_pem) = identity.pem_pair()?;
    build_quic_server_config_from_pem(&cert_pem, &key_pem, alpn_protocols)
}

/// Builds a QUIC server config from PEM-encoded identity material and ALPN policy.
pub fn build_quic_server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ServerConfig> {
    let cert_chain = rustls_pemfile::certs(&mut &*cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse TLS certificate PEM")?;
    ensure!(!cert_chain.is_empty(), "no certificate found in TLS PEM");
    let key = rustls_pemfile::private_key(&mut &*key_pem)
        .context("failed to parse TLS private key PEM")?
        .context("no private key found in TLS PEM")?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("failed to build TLS server config")?;
    tls.alpn_protocols = alpn_protocols;
    Ok(ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .context("failed to build QUIC server config")?,
    )))
}

fn quic_client_config(tls: rustls::ClientConfig) -> Result<ClientConfig> {
    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    )))
}

#[derive(Debug)]
struct InsecureServerCertVerifier;

impl ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("stargate-tls-{}-{id}", std::process::id()));
            fs::create_dir(&path).expect("create TLS test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn install_projected_generation(
        root: &Path,
        generation: &str,
        cert_pem: &[u8],
        key_pem: &[u8],
    ) {
        use std::os::unix::fs::symlink;

        let generation_dir = root.join(generation);
        fs::create_dir(&generation_dir).expect("create projected generation");
        fs::write(generation_dir.join("tls.crt"), cert_pem).expect("write projected cert");
        fs::write(generation_dir.join("tls.key"), key_pem).expect("write projected key");

        let next_data = root.join("..data-next");
        let _ = fs::remove_file(&next_data);
        symlink(generation, &next_data).expect("create projected data symlink");
        fs::rename(next_data, root.join("..data")).expect("swap projected data symlink");

        if !root.join("tls.crt").exists() {
            symlink("..data/tls.crt", root.join("tls.crt")).expect("create projected cert symlink");
            symlink("..data/tls.key", root.join("tls.key")).expect("create projected key symlink");
        }
    }

    #[cfg(unix)]
    fn install_projected_trust_generation(root: &Path, generation: &str, trust_pem: &[u8]) {
        use std::os::unix::fs::symlink;

        let generation_dir = root.join(generation);
        fs::create_dir(&generation_dir).expect("create projected trust generation");
        fs::write(generation_dir.join("ca.crt"), trust_pem).expect("write projected trust bundle");

        let next_data = root.join("..data-next");
        let _ = fs::remove_file(&next_data);
        symlink(generation, &next_data).expect("create projected data symlink");
        fs::rename(next_data, root.join("..data")).expect("swap projected data symlink");

        if !root.join("ca.crt").exists() {
            symlink("..data/ca.crt", root.join("ca.crt")).expect("create projected trust symlink");
        }
    }

    #[cfg(unix)]
    #[test]
    fn server_identity_reloader_follows_atomic_projected_volume_update() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let root = TestDir::new();
        let (first_cert, first_key) =
            generate_self_signed_cert_for_names(vec!["first.example.test".to_string()]).unwrap();
        let (second_cert, second_key) =
            generate_self_signed_cert_for_names(vec!["second.example.test".to_string()]).unwrap();
        install_projected_generation(root.path(), "..2026_01", &first_cert, &first_key);

        let mut reloader =
            ServerIdentityReloader::load(root.path().join("tls.crt"), root.path().join("tls.key"))
                .expect("load initial identity");
        assert_eq!(
            reloader.current_identity(),
            &ServerTlsIdentity::Provided {
                cert_pem: first_cert,
                key_pem: first_key,
            }
        );

        install_projected_generation(root.path(), "..2026_02", &second_cert, &second_key);

        let replacement = reloader
            .reload_if_changed()
            .expect("reload projected identity")
            .expect("replacement should be detected");
        assert_eq!(
            replacement,
            ServerTlsIdentity::Provided {
                cert_pem: second_cert.clone(),
                key_pem: second_key.clone(),
            }
        );
        assert_eq!(
            reloader.current_identity(),
            &ServerTlsIdentity::Provided {
                cert_pem: second_cert,
                key_pem: second_key,
            }
        );
    }

    async fn connect_with_trust(server: &quinn::Endpoint, trusted_cert_pem: &[u8]) -> Result<()> {
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
        client.set_default_client_config(build_trusted_quic_client_config_with_alpn(
            trusted_cert_pem,
            Vec::new(),
        )?);
        let connecting = client.connect(server.local_addr()?, "localhost")?;
        let incoming = server.accept().await.context("server endpoint closed")?;
        let (client_connection, server_connection) = tokio::join!(connecting, incoming);
        let client_connection = client_connection?;
        let server_connection = server_connection?;
        client_connection.close(0u32.into(), b"test complete");
        server_connection.close(0u32.into(), b"test complete");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn server_identity_reloader_updates_new_quic_handshakes() -> Result<()> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let root = TestDir::new();
        let (first_cert, first_key) = generate_self_signed_cert().unwrap();
        let (second_cert, second_key) = generate_self_signed_cert().unwrap();
        install_projected_generation(root.path(), "..2026_01", &first_cert, &first_key);
        let mut reloader =
            ServerIdentityReloader::load(root.path().join("tls.crt"), root.path().join("tls.key"))
                .unwrap();
        let initial_config = build_quic_server_config(reloader.current_identity(), Vec::new())?;
        let server = quinn::Endpoint::server(initial_config, "127.0.0.1:0".parse().unwrap())?;

        connect_with_trust(&server, &first_cert).await?;
        install_projected_generation(root.path(), "..2026_02", &second_cert, &second_key);

        assert!(reloader.reload_quic_server_config_if_changed(&server, Vec::new())?);
        connect_with_trust(&server, &second_cert).await?;
        assert!(connect_with_trust(&server, &first_cert).await.is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn server_identity_watch_rejects_invalid_generation_then_activates_valid_generation()
    -> Result<()> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let root = TestDir::new();
        let (first_cert, first_key) = generate_self_signed_cert().unwrap();
        let (second_cert, second_key) = generate_self_signed_cert().unwrap();
        install_projected_generation(root.path(), "..2026_01", &first_cert, &first_key);
        let reloader =
            ServerIdentityReloader::load(root.path().join("tls.crt"), root.path().join("tls.key"))?;
        let initial_config = build_quic_server_config(reloader.current_identity(), Vec::new())?;
        let server = quinn::Endpoint::server(initial_config, "127.0.0.1:0".parse().unwrap())?;
        let shutdown = tokio_util::sync::CancellationToken::new();
        let watcher = tokio::spawn(run_quic_server_identity_reloader(
            reloader,
            server.clone(),
            Vec::new(),
            std::time::Duration::from_millis(10),
            shutdown.clone(),
        ));

        install_projected_generation(root.path(), "..2026_bad", &second_cert, &first_key);
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        connect_with_trust(&server, &first_cert).await?;
        assert!(connect_with_trust(&server, &second_cert).await.is_err());

        install_projected_generation(root.path(), "..2026_02", &second_cert, &second_key);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if connect_with_trust(&server, &second_cert).await.is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .context("valid replacement was not activated")?;

        shutdown.cancel();
        watcher.await??;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn client_trust_reloader_publishes_only_valid_projected_updates() -> Result<()> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let root = TestDir::new();
        let (first_cert, _) = generate_self_signed_cert().unwrap();
        let (second_cert, _) = generate_self_signed_cert().unwrap();
        install_projected_trust_generation(root.path(), "..2026_01", &first_cert);

        let (reloader, provider) = ClientTrustReloader::load(root.path().join("ca.crt"))?;
        let mut updates = provider.subscribe();
        assert_eq!(provider.current_pem(), first_cert);
        let shutdown = tokio_util::sync::CancellationToken::new();
        let watcher = tokio::spawn(run_client_trust_reloader(
            reloader,
            Duration::from_millis(10),
            shutdown.clone(),
        ));

        install_projected_trust_generation(root.path(), "..2026_bad", b"");
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(provider.current_pem(), first_cert);
        assert!(!updates.has_changed()?);

        install_projected_trust_generation(root.path(), "..2026_02", &second_cert);
        tokio::time::timeout(Duration::from_secs(1), updates.changed())
            .await
            .context("valid trust replacement was not published")??;
        assert_eq!(provider.current_pem(), second_cert);

        shutdown.cancel();
        watcher.await??;
        Ok(())
    }

    #[test]
    fn self_signed_cert_produces_nonempty_pem() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (cert_pem, key_pem) = generate_self_signed_cert().unwrap();
        assert!(!cert_pem.is_empty());
        assert!(!key_pem.is_empty());
    }

    #[test]
    fn self_signed_cert_for_names_produces_nonempty_pem() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (cert_pem, key_pem) =
            generate_self_signed_cert_for_names(vec!["sg-b.stargate.external".to_string()])
                .unwrap();
        assert!(!cert_pem.is_empty());
        assert!(!key_pem.is_empty());
    }

    fn cert_with_validity(
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> (Vec<u8>, Vec<u8>) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = rcgen::date_time_ymd(not_after.0, not_after.1, not_after.2);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    #[test]
    fn server_identity_reloader_rejects_expired_and_not_yet_valid_certificates() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let root = TestDir::new();
        let cert_path = root.path().join("tls.crt");
        let key_path = root.path().join("tls.key");

        let (expired_cert, expired_key) = cert_with_validity((2020, 1, 1), (2021, 1, 1));
        fs::write(&cert_path, expired_cert).unwrap();
        fs::write(&key_path, expired_key).unwrap();
        assert!(ServerIdentityReloader::load(cert_path.clone(), key_path.clone()).is_err());

        let (future_cert, future_key) = cert_with_validity((2035, 1, 1), (2036, 1, 1));
        fs::write(&cert_path, future_cert).unwrap();
        fs::write(&key_path, future_key).unwrap();
        assert!(ServerIdentityReloader::load(cert_path, key_path).is_err());
    }

    #[test]
    fn server_identity_reloader_rejects_expired_intermediate_certificate() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let root = TestDir::new();
        let cert_path = root.path().join("tls.crt");
        let key_path = root.path().join("tls.key");

        let mut issuer_params = rcgen::CertificateParams::default();
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        issuer_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        issuer_params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let issuer_key = rcgen::KeyPair::generate().unwrap();
        let issuer = issuer_params.self_signed(&issuer_key).unwrap();

        let leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer, &issuer_key)
            .unwrap();
        let chain_pem = format!("{}{}", leaf.pem(), issuer.pem()).into_bytes();
        let key_pem = leaf_key.serialize_pem().into_bytes();
        let identity = ServerTlsIdentity::Provided {
            cert_pem: chain_pem.clone(),
            key_pem: key_pem.clone(),
        };
        let leaf_validity = server_identity_validity(&identity).unwrap().unwrap();
        let effective_validity = server_identity_effective_validity(&identity)
            .unwrap()
            .unwrap();
        assert!(effective_validity.not_after_unix_seconds < leaf_validity.not_after_unix_seconds);

        fs::write(&cert_path, chain_pem).unwrap();
        fs::write(&key_path, key_pem).unwrap();

        assert!(ServerIdentityReloader::load(cert_path, key_path).is_err());
    }

    #[test]
    fn reloaders_reject_oversized_material_before_activation() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let root = TestDir::new();
        let oversized = vec![b'x'; MAX_TLS_MATERIAL_BYTES as usize + 1];
        let trust_path = root.path().join("ca.crt");
        fs::write(&trust_path, &oversized).unwrap();
        assert!(ClientTrustReloader::load(trust_path).is_err());

        let cert_path = root.path().join("tls.crt");
        let key_path = root.path().join("tls.key");
        fs::write(&cert_path, oversized).unwrap();
        fs::write(&key_path, b"key").unwrap();
        assert!(ServerIdentityReloader::load(cert_path, key_path).is_err());
    }

    #[test]
    fn repeated_rejected_generation_is_debounced_until_contents_change() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let root = TestDir::new();
        let trust_path = root.path().join("ca.crt");
        let (initial_cert, _) = generate_self_signed_cert().unwrap();
        fs::write(&trust_path, &initial_cert).unwrap();
        let (mut reloader, _) = ClientTrustReloader::load(trust_path.clone()).unwrap();

        fs::write(&trust_path, b"invalid trust generation").unwrap();
        assert!(reloader.load_candidate().is_err());
        assert!(reloader.load_candidate().unwrap().is_none());

        let (replacement_cert, _) = generate_self_signed_cert().unwrap();
        fs::write(&trust_path, &replacement_cert).unwrap();
        let candidate = reloader
            .load_candidate()
            .unwrap()
            .expect("changed valid generation should be retried");
        reloader.commit(candidate);
        assert_eq!(reloader.current_pem(), replacement_cert);
    }

    #[test]
    fn insecure_client_config_succeeds() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let _config = build_insecure_quic_client_config().unwrap();
    }

    #[test]
    fn insecure_client_config_with_alpn_succeeds() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let _config = build_insecure_quic_client_config_with_alpn(vec![b"h3".to_vec()]).unwrap();
    }

    #[test]
    fn trusted_client_config_with_alpn_accepts_pem_root() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let (cert_pem, _) = generate_self_signed_cert().unwrap();
        let _config =
            build_trusted_quic_client_config_with_alpn(&cert_pem, vec![b"h3".to_vec()]).unwrap();
    }

    #[test]
    fn trusted_client_config_rejects_empty_trust_bundle() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        assert!(build_trusted_quic_client_config_with_alpn(b"", Vec::new()).is_err());
    }

    #[test]
    fn server_tls_identity_requires_complete_pem_pair() {
        let cert_pem = b"cert".to_vec();
        let key_pem = b"key".to_vec();

        assert!(matches!(
            ServerTlsIdentity::from_optional_pem(None, None).unwrap(),
            ServerTlsIdentity::SelfSigned
        ));
        assert_eq!(
            ServerTlsIdentity::from_optional_pem(Some(cert_pem.clone()), Some(key_pem.clone()))
                .unwrap(),
            ServerTlsIdentity::Provided {
                cert_pem: cert_pem.clone(),
                key_pem: key_pem.clone(),
            }
        );
        assert!(ServerTlsIdentity::from_optional_pem(Some(cert_pem), None).is_err());
        assert!(ServerTlsIdentity::from_optional_pem(None, Some(key_pem)).is_err());
    }

    #[test]
    fn ordered_dial_candidates_prioritize_ipv4_without_discarding_ipv6() {
        let ipv6: SocketAddr = "[fd00::1]:50072"
            .parse()
            .expect("IPv6 address should parse");
        let ipv4: SocketAddr = "10.0.0.4:50072".parse().expect("IPv4 address should parse");

        assert_eq!(ordered_dial_candidates([ipv6, ipv4]), vec![ipv4, ipv6]);
        assert_eq!(quic_client_bind_addr(ipv4), "0.0.0.0:0".parse().unwrap());
        assert_eq!(quic_client_bind_addr(ipv6), "[::]:0".parse().unwrap());
    }
}
