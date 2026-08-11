---
---

# Rotate Transport TLS Material

Stargate, Pylon, and `stargate-k8s-router` reload mounted TLS files without a
process restart. A valid replacement becomes active within 30 seconds after
Kubernetes exposes the complete projected-volume generation. The default poll
interval is 10 seconds.

Server certificate and private-key files are loaded as one generation. Client
trust bundles are also validated before activation. An invalid, empty,
oversized, expired, not-yet-valid, incomplete, or mismatched replacement is
rejected. The process keeps its last-known-good material and does not enable
insecure mode as a fallback.

## Plan an overlapping CA rotation

Use this order to avoid a trust gap:

1. Add the new CA certificate to every client trust bundle. Keep the old CA in
   the bundle.
2. Wait for each component to report a successful `client_trust` reload.
3. Replace each server certificate and private key with an identity signed by
   the new CA.
4. Wait for each component to report a successful `server_identity` reload.
5. Verify new connections through Stargate, Pylon, and
   `stargate-k8s-router`.
6. Remove the old CA from every client trust bundle.
7. Verify that connections using the old CA fail.

Every trust-bundle change closes connections created with the previous client
trust generation. The client reconnects with the replacement bundle. Server
identity changes apply to new handshakes and do not close established
connections.

## Perform emergency CA revocation

Replace the affected trust bundle with a valid bundle that omits the revoked
CA. Do not wait for established connections to drain. A successful reload
closes connections that use the old client trust generation and forces a new
TLS handshake.

If the active server identity is signed only by the revoked CA, install a new
identity and trust bundle as one coordinated operation. Keep every certificate
and private-key pair in the same Kubernetes Secret so the projected `..data`
symlink exposes one complete generation.

## Verify a rotation

Check the projected generation inside each pod:

```bash
kubectl exec -n <namespace> <pod> -- readlink -f <tls-mount>/tls.crt
kubectl exec -n <namespace> <pod> -- readlink -f <tls-mount>/tls.key
```

Check reload counters and the active server certificate expiry:

```bash
curl -fsS http://<metrics-endpoint>/metrics | grep tls_reloads_total
curl -fsS http://<metrics-endpoint>/metrics | grep tls_certificate_expiry_seconds
```

The counters use only `material_type` and `result` labels. Expected material
types are `server_identity` and `client_trust`. Expected results are `success`
and `rejected`.

Check component readiness after server identity rotation:

```bash
curl -fsS http://<health-endpoint>/readyz
```

An active server identity that expires before a valid replacement is installed
makes Stargate, Pylon, or `stargate-k8s-router` not ready. Pylon serves
`/readyz` from its metrics endpoint.

## Recover from a rejected reload

1. Check the component log for `TLS material reload rejected`.
2. Confirm that the certificate, private key, and trust bundle are non-empty
   PEM files.
3. Confirm that the certificate and key match and that every certificate in
   the served chain is currently valid.
4. Publish a complete corrected Secret or ConfigMap generation.
5. Wait for a successful reload counter increment.
6. Test a new connection with the expected CA and server name.

A rejected later generation does not interrupt the last-known-good
configuration. If no valid material can be loaded during startup, the process
fails startup instead of weakening TLS.
