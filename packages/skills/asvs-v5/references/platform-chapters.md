# ASVS v5.0.0 Chapters V11 through V17: Platform, Crypto, Resilience

Detailed catalog for the chapters governing cryptographic primitives, infrastructure configuration, data privacy, secure coding paradigms, security logging, and WebRTC.

---

## V11: Cryptography

Encryption algorithms, hashing, RNG, public key infrastructure.

### V11.1 Cryptographic Inventory (documentation prerequisite)

Required: full inventory of cryptographic operations in the application, algorithm choices, key lifecycle (generation, rotation, destruction), key storage location, post-quantum readiness assessment.

* **Modality**: agentic.
* **Failure**: document missing. Halt V11 verification.

### V11.2 Algorithm Selection

**V11.2.1 (L1)**: only approved algorithms in use.

* **Modality**: deterministic.
* **Signal**: algorithm string literals in cipher / hash invocations.
* **Approved (2025 baseline)**:
  * Symmetric: AES-256-GCM, AES-256-CBC with HMAC, ChaCha20-Poly1305.
  * Asymmetric: RSA >= 2048 (>= 3072 preferred), ECDSA P-256/P-384, Ed25519.
  * Hash: SHA-256, SHA-384, SHA-512, SHA-3.
  * Password: Argon2id, bcrypt (cost >= 12), scrypt, PBKDF2 (iterations >= 600,000).
* **Hard failures (flag unconditionally)**: DES, 3DES, RC4, MD5 (except for non-security checksums; agent verifies context), SHA-1 for signatures, ECB mode for any cipher.
* **Patterns**:
  * Java: `Cipher.getInstance("DES/...")`, `Cipher.getInstance("AES/ECB/...")`, `MessageDigest.getInstance("MD5")` in security context.
  * Python: `Crypto.Cipher.DES`, `algorithms.ARC4()`, `hashlib.md5()` in security context.
  * Node: `crypto.createCipheriv('des-...', ...)`, `crypto.createHash('md5')` in security context.
  * Go: `crypto/des`, `crypto/rc4`.

### V11.3 Random Number Generation

**V11.3.1 (L1)**: security-relevant randomness uses CSPRNG.

* **Modality**: deterministic.
* **Signal**: token / nonce / salt generation. Flag `Math.random()`, `java.util.Random`, Python `random` module, Go `math/rand` in security contexts.
* **Approved**: `crypto.randomBytes` (Node), `secrets` module (Python), `java.security.SecureRandom`, `crypto/rand` (Go).
* **False positives**: `Math.random()` for non-security UI animation, A/B test bucketing where collision is acceptable. Agent disambiguates by context.

### V11.4 IV / Nonce Reuse

**V11.4 (L2)**: IVs and nonces are not reused under the same key.

* **Modality**: deterministic with limits.
* **Signal**: hardcoded IV literal passed to AES-GCM, AES-CTR, ChaCha20. Flag `Buffer.alloc(12, 0)` or similar zero-filled IV passed to authenticated encryption.

### V11.5 Key Storage

**V11.5 (L1)**: keys are not in source.

* **Modality**: deterministic.
* **Signal**: GitLeaks + Trivy secrets scanning. Cross-reference V13.

---

## V12: Secure Communication

TLS, certificate validation, secure communication channel configuration.

### V12.1 Transport Layer Security

**V12.1.1 (L1)**: HTTPS enforced; HTTP redirects to HTTPS.

* **Modality**: deterministic.
* **Signal**: IaC parsing.
  * Kubernetes Ingress: `nginx.ingress.kubernetes.io/force-ssl-redirect: "true"` or `ssl-redirect: "true"`.
  * AWS ALB: listener on 80 with redirect action to 443.
  * Cloudflare: `always_use_https = true`.
  * Application middleware: HSTS-aware redirect.
* **Failure pattern**: HTTP listener serving content directly; missing redirect rule.

**V12.1.2 (L2)**: TLS 1.2 minimum, TLS 1.3 preferred. TLS 1.0 / 1.1 / SSLv3 disabled.

* **Modality**: deterministic.
* **Signal**: TLS protocol configuration in load balancer policy, web server config, application config.

### V12.2 Certificate Validation

**V12.2 (L1)**: outbound HTTPS clients validate certificates.

* **Modality**: deterministic.
* **Signal**: HTTP client configuration. Flag `rejectUnauthorized: false` (Node), `verify=False` (Python requests), `InsecureSkipVerify: true` (Go), `-k` / `--insecure` in shell scripts. Production code should never disable verification; flag aggressively.
* **False positives**: test fixtures, local-dev configs guarded by environment checks. Agent verifies guard.

### V12.3 Internal Service Communication

**V12.3 (L2)**: internal service-to-service traffic is encrypted (mTLS or service mesh).

* **Modality**: hybrid.
* **Signal**: service mesh config (Istio PeerAuthentication, Linkerd policy), or explicit TLS in client config for internal endpoints.

---

## V13: Configuration

Application frameworks, third-party libraries, environment variables, build pipelines.

### V13.1 Dependency Management (SCA)

**V13.1.1 (L1)**: no known-vulnerable dependencies at high or critical severity.

* **Modality**: deterministic.
* **Signal**: Trivy / Snyk / OSV-Scanner output cross-referenced against NVD CVE feed.
* **Manifest scope**: `package-lock.json`, `pom.xml`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, `requirements.txt` with pinned versions, `pyproject.toml`.
* **Canonical examples**: `log4j-core` < 2.17.1 (Log4Shell), `lodash` versions vulnerable to prototype pollution, `xz-utils` 5.6.0/5.6.1 (CVE-2024-3094 backdoor).

### V13.2 Pipeline Hardening

**V13.2 (L2)**: CI/CD pipelines pin actions/images by SHA, not floating tags.

* **Modality**: deterministic.
* **Signal**: `.github/workflows/*.yml` references using `@v3` (mutable) versus `@<sha>` (immutable). Recommend SHA pinning for third-party actions, especially those with secrets access.

### V13.3 Secret Storage

**V13.3.1 (L1)**: no hardcoded secrets.

* **Modality**: deterministic.
* **Signal**: GitLeaks (entropy + regex), Trivy secrets, custom Semgrep rules for known secret formats (AWS keys, GCP service account JSONs, Stripe keys, Slack webhooks).
* **False positives**: example values, test fixtures, public keys. Configure `.gitleaksignore` for known-safe paths.

**V13.3.2 (L2)**: secrets are scoped, rotated, and revocable.

* **Modality**: agentic.
* **Signal**: agent reads secret-management policy and verifies the application loads from a manager (AWS Secrets Manager, Vault, GCP Secret Manager, Doppler) rather than long-lived environment variables.

### V13.4 Configuration Defaults

**V13.4 (L1)**: production configuration disables debug, verbose error pages, default credentials.

* **Modality**: deterministic.
* **Signal**: framework debug flags. `DEBUG = True` in Django production config, `app.debug = True` in Flask, `NODE_ENV !== 'production'` paths reachable in production. Default admin credentials in seed data files.

---

## V14: Data Protection

Sensitive data at rest, in transit, on the client; data retention; privacy.

### V14.1 Data Classification (prerequisite)

Required: data inventory, sensitivity tiers (Public, Internal, Confidential, Restricted), retention policy, deletion procedure.

### V14.2 Encryption at Rest

**V14.2 (L2)**: data classified Confidential or Restricted is encrypted at rest.

* **Modality**: hybrid.
* **Signal (deterministic)**: storage IaC. Cloud bucket encryption flags (`server_side_encryption_configuration`), database encryption settings (`storage_encrypted = true` for RDS, transparent data encryption for SQL Server), volume encryption.
* **Signal (agentic)**: agent reads data classification, identifies fields tagged Confidential or Restricted in the schema, verifies the encryption pathway for those fields.

### V14.3 Data Minimization

**V14.3 (L2)**: only necessary data is collected and retained.

* **Modality**: agentic.
* **Signal**: agent reviews API responses and database schema against the data inventory. Flags fields collected but not used or retained beyond the documented retention window.

### V14.4 Sensitive Data in Logs

**V14.4 (L1)**: sensitive data is not written to logs.

* **Modality**: hybrid.
* **Signal (deterministic)**: log statements containing variables named `password`, `token`, `ssn`, `cardNumber`, `api_key`. Custom Semgrep rules per data classification tags.
* **Signal (agentic)**: agent reads logging middleware to verify PII redaction is centralized.

### V14.5 Client-Side Storage

**V14.5 (L2)**: sensitive data is not persisted in `localStorage`, `sessionStorage`, or IndexedDB unless encrypted with a per-session key not stored alongside.

* **Modality**: deterministic.
* **Signal**: `localStorage.setItem` calls with sensitive payloads (cross-references V10.5).

---

## V15: Secure Coding

Defensive coding patterns, memory safety, resilient architecture.

### V15.1 Dynamic Code Execution

**V15.1 (L1)**: no dynamic evaluation of user input.

* **Modality**: deterministic.
* **Signal**: `eval()`, `Function()` constructor with concatenated input, `setTimeout(string, ...)` / `setInterval(string, ...)` (string form), Python `exec()` / `eval()`, Ruby `eval` / `instance_eval`, PHP `eval`.

### V15.2 Type Safety

**V15.2 (L2)**: language type guarantees are not subverted.

* **Modality**: deterministic.
* **Signal**: TypeScript `any` / `as any` in security-sensitive paths, `unsafe` blocks in Rust without justification comment, JNI / FFI calls without bounds documentation.

### V15.3 Memory Safety (C/C++ scope)

**V15.3 (L2)**: pointer arithmetic is bounds-checked; manual memory management uses RAII or smart pointers.

* **Modality**: deterministic.
* **Signal**: raw `new` / `delete`, raw `malloc` / `free`, manual buffer arithmetic. Recommend `std::unique_ptr`, `std::span`, `std::string`.

---

## V16: Security Logging

Auditable security events, safe error handling, prevention of sensitive data leakage.

### V16.1 Security Event Logging

**V16.1 (L2)**: authentication, authorization, and high-impact operations are logged with timestamp, actor, action, target, outcome.

* **Modality**: agentic.
* **Signal**: agent reviews authentication and authorization paths for explicit logging calls. Verifies log schema includes the required fields. Flags critical-event paths missing log emission.

### V16.2 Error Handling

**V16.2 (L1)**: errors do not leak sensitive details to clients.

* **Modality**: deterministic.
* **Signal**: catch blocks that pass `error.stack`, `error.message` raw to HTTP response. Flag `res.status(500).send(err)` patterns, `res.json({ error: err.toString() })`. Production must return generic error identifiers; full detail goes to server-side logs only.

### V16.3 Log Integrity

**V16.3 (L2)**: logs are protected against tampering and unauthorized access.

* **Modality**: hybrid.
* **Signal**: external log shipping configuration (Datadog, Splunk, CloudWatch). Append-only retention. Application service account does not have log-deletion permission on the log store.

### V16.4 PII in Logs

**V16.4 (L1)**: PII is masked or omitted in log output.

* **Modality**: hybrid; cross-references V14.4.

---

## V17: WebRTC (new in v5.0.0)

Media streams, signaling protocols, TURN/STUN server controls.

### V17.1 Transport Security

**V17.1 (L1)**: SRTP for media; DTLS for the SCTP / data channel handshake.

* **Modality**: deterministic.
* **Signal**: WebRTC peer-connection configuration. RTCConfiguration includes ICE servers over TURNS (TURN over TLS) or STUN over secured channel. SDP negotiation enforces SRTP profiles (`RTP/SAVPF`), not unencrypted `RTP/AVPF`.

### V17.2 Signaling Channel

**V17.2 (L1)**: signaling occurs over WSS (WebSocket Secure) or HTTPS.

* **Modality**: deterministic.
* **Signal**: signaling client uses `wss://` / `https://`, never `ws://` / `http://`.

### V17.3 TURN Authentication

**V17.3 (L2)**: TURN credentials are short-lived (ephemeral, e.g., HMAC-based time-limited credentials), not long-lived shared secrets.

* **Modality**: deterministic.
* **Signal**: TURN credential generation logic. Flag long-lived static TURN passwords in config.

### V17.4 Media Permission Lifecycle

**V17.4 (L2)**: camera/microphone permission is requested per session, with explicit user gesture, and released on disconnect.

* **Modality**: agentic.
* **Signal**: `getUserMedia` invocations and corresponding `stop()` calls on tracks during teardown.

---

## Cross-references

* For NIST/CIS/ISO/SOC 2 mappings: `cross-framework.md`.
* For tool orchestration patterns covering V11 (Semgrep crypto rules), V13 (Trivy + GitLeaks), V12 (IaC parsing): `violations-and-tools.md`.
