# ASVS v5.0.0 Chapters V6 through V10: Identity and Access

Detailed catalog for the chapters governing the entire identity lifecycle: authentication, session, authorization, self-contained tokens, OAuth/OIDC. V8 (Authorization) is the highest-leverage chapter for agentic verification; broken access control is the #1 OWASP Top 10 entry and is largely invisible to deterministic SAST.

---

## V6: Authentication

Identity proofing, password security, MFA, identity provider integration.

### V6.1 Authentication Decisions (documentation prerequisite)

Required: authentication factors per assurance level, IdP relationships, password policy, MFA enrollment flow, account recovery flow, session establishment semantics.

* **Modality**: agentic.
* **Failure**: document missing. Halt V6 verification.

### V6.2 Password Security

**V6.2.1 (L1)**: passwords stored using a memory-hard or work-factor-tunable hash with salt.

* **Modality**: deterministic.
* **Signal**: hash function invocation. Acceptable: Argon2id (preferred), bcrypt with cost >= 12, scrypt with appropriate parameters, PBKDF2-HMAC-SHA256 with iterations >= 600,000 (OWASP 2023 baseline).
* **Failure patterns**: `MD5(password)`, `SHA1(password)`, `SHA256(password)` without HMAC + salt, `crypt()` without specifier, custom-rolled hashing, plaintext storage.
* **Cross-framework**: NIST IA-5, ISO A.5.17, SOC 2 CC6.1.

**V6.2.2 (L1)**: password length minimum 8 (L1) / 12 (L2); no composition rules (no forced character classes); breach-list check on creation.

* **Modality**: deterministic.
* **Signal**: validation rules in registration / password-change handlers. Flag patterns enforcing uppercase + digit + symbol counts; recommend HaveIBeenPwned k-anonymity check.

### V6.3 Multi-Factor Authentication

**V6.3 (L2)**: MFA available for all users; required for privileged accounts and sensitive operations.

* **Modality**: hybrid.
* **Signal (deterministic)**: presence of TOTP / WebAuthn / push library; route protection middleware that enforces MFA for admin paths.
* **Signal (agentic)**: agent reads `authentication-policy.md` to determine which roles MUST have MFA and verifies enforcement matches.
* **Failure pattern**: MFA enabled at the user level but not enforced at sensitive endpoints (e.g., `/admin/*` does not require an active MFA assertion).

### V6.4 Account Recovery

**V6.4 (L2)**: recovery does not weaken the authentication factor. Recovery tokens are single-use, time-limited (<= 60 minutes), bound to the requesting context.

* **Modality**: deterministic.
* **Signal**: token TTL configuration; single-use semantics (token is invalidated on first redemption, before the password mutation occurs).

### V6.5 Credential Storage

**V6.5 (L2)**: credentials at rest are encrypted; transport is TLS-only.

* **Modality**: hybrid; cross-references V12.

---

## V7: Session Management

Session lifecycle, timeouts, secure termination, federated re-authentication, defense against hijacking.

### V7.1 Session Decisions (documentation prerequisite)

Required: idle timeout, absolute timeout, re-authentication thresholds for sensitive operations, federated session relationship to IdP.

### V7.2 Session Identifier Generation

**V7.2 (L1)**: session identifiers are cryptographically random, at least 64 bits of entropy.

* **Modality**: deterministic.
* **Signal**: framework session middleware uses CSPRNG. Flag custom session IDs built from `Math.random()`, timestamps, or user attributes.

### V7.3 Timeout

**V7.3 (L2)**: idle timeout enforced server-side; absolute timeout independent of activity.

* **Modality**: hybrid.
* **Signal (deterministic)**: session config values (e.g., `cookie.maxAge`, framework session timeout). Compare against the documented value in `session-policy.md`.
* **Signal (agentic)**: agent verifies the timeout value matches policy. Flag JWTs with `expiresIn` exceeding the documented session lifetime, e.g., `jwt.sign(payload, secret, { expiresIn: '10y' })` against a policy of 8h.

### V7.4 Session Termination

**V7.4.1 (L2)**: logout invalidates the session server-side.

* **Modality**: agentic.
* **Signal**: agent reads the logout controller. Required: server-side session destruction or token revocation list update. Failure: client-side cookie deletion only, with server-side session record still valid.
* **For JWTs**: short access token TTL + revocation list for refresh tokens; or rotate signing keys; or accept the architectural tradeoff and document it.

### V7.5 Re-Authentication

**V7.5 (L2)**: sensitive operations (password change, MFA enrollment, payment authorization) require recent authentication, not merely an active session.

* **Modality**: agentic.
* **Signal**: agent verifies sensitive endpoints check a `last_auth_time` claim or trigger a step-up flow.

---

## V8: Authorization

The most important chapter for agentic verification. Broken access control and IDOR cannot be detected by syntax alone.

### V8.1 Authorization Documentation (documentation prerequisite, MANDATORY)

Required: role hierarchy, permission matrix, data ownership model, resource-to-owner relationships, attribute-based access control (ABAC) rules if applicable.

* **Modality**: agentic.
* **Failure**: document missing. Halt V8 verification entirely. Without an ownership model the agent cannot reason about IDOR.

### V8.2 Operation-Level Authorization

**V8.2.1 (L2)**: every state-changing endpoint enforces server-side authorization.

* **Modality**: agentic.
* **Signal**: agent enumerates routes from OpenAPI/router config, identifies state-changing methods (POST, PUT, PATCH, DELETE), and verifies each route invokes an authorization middleware or explicit check before the mutation.
* **Failure pattern**: `app.post('/api/updateRole', (req, res) => { db.users.update(req.body.userId, { role: req.body.role }) })` with no `requireAdmin` middleware. The developer relied on the frontend hiding the UI button. Frontend-only access control is the canonical broken access control failure.

**V8.2.2 (L2)**: IDOR / direct object reference protection.

* **Modality**: agentic.
* **Signal**: routes accepting an object identifier (`/api/user/:userId/financial`, `/api/order/:orderId`, `/api/document/:docId`) verify the requesting user's relationship to the resource. Required: explicit ownership check or scoped query (`SELECT * FROM orders WHERE id = ? AND user_id = ?`).
* **Failure pattern**: scoped query absent; ownership check absent; reliance on the identifier being unguessable (UUIDs help but do not satisfy the requirement).

### V8.3 Privilege Escalation

**V8.3 (L2)**: vertical privilege escalation prevented; role assignments cannot be modified by the holder.

* **Modality**: agentic.
* **Signal**: agent reviews role-mutation endpoints. Required: role changes are audit-logged; the modifying user has higher privilege than both the source and target role; users cannot self-elevate.

### V8.4 Multi-Tenant Isolation

**V8.4 (L2)**: tenant boundary enforced at the data layer.

* **Modality**: agentic.
* **Signal**: every query against tenant-scoped tables includes a `WHERE tenant_id = ?` clause matching the authenticated tenant. Row-Level Security (Postgres RLS, Supabase RLS) policies present and tested.
* **Failure pattern**: tenant ID derived from request body or query parameter rather than from the authenticated session.

---

## V9: Self-Contained Tokens (new in v5.0.0)

Validation of source, cryptographic integrity, and content payload of stateless tokens, predominantly JWTs.

### V9.1 JWT Algorithm Pinning

**V9.1.1 (L1)**: token verification pins the algorithm.

* **Modality**: deterministic.
* **Signal**: JWT verification calls explicitly specify `algorithms: ['RS256']` or `['ES256']` or `['EdDSA']`. Flag `jwt.verify(token, key)` without the algorithms parameter (library defaults vary; some accept the algorithm declared in the token header, enabling the algorithm-confusion attack).
* **Hard failure**: any code path accepting `alg: none`. Flag unconditionally.

### V9.1.2 (L1): no key confusion between asymmetric and symmetric.

* **Signal**: when using RS256 / ES256, the verification key is loaded as a public key (PEM, JWK), never reused as an HMAC secret. Flag patterns where a public key is also passed to HS256 verification, enabling the classic algorithm-confusion attack.

### V9.2 JWT Claims Validation

**V9.2 (L2)**: tokens verify `iss`, `aud`, `exp`, `nbf`, `iat`. The audience claim matches the validating service.

* **Modality**: deterministic.
* **Signal**: verification config sets `issuer`, `audience` (or library equivalent). Flag verification that ignores audience.

### V9.3 Key Management

**V9.3 (L1)**: signing keys are not hardcoded.

* **Modality**: deterministic.
* **Signal**: GitLeaks entropy-based detection of high-entropy strings near `jwt.sign` calls. Required: keys loaded from environment variables, secret manager, or KMS.
* **Failure pattern**: `const SECRET = "supersecretkey123"`. Also flag committed `.env` files containing JWT secrets.

### V9.4 Token Lifetime

**V9.4 (L2)**: access tokens are short-lived (typically <= 15 minutes). Refresh tokens are stored server-side and rotated.

* **Modality**: hybrid.
* **Signal (deterministic)**: `expiresIn` value at signing time. Compare against `session-policy.md`.

---

## V10: OAuth and OIDC (new in v5.0.0)

Authorization flow security, OAuth client configuration, resource server policies, consent management.

### V10.1 OAuth Decisions (prerequisite)

Required: client type per integration (public / confidential), grant types in use, scope catalog, consent semantics, IdP relationships.

### V10.2 PKCE

**V10.2.1 (L1)**: public clients use PKCE (Proof Key for Code Exchange).

* **Modality**: deterministic.
* **Signal**: OAuth client library configuration. Required for any non-confidential client (SPA, mobile, native): `code_verifier` and `code_challenge` (with `code_challenge_method=S256`) participate in the flow.
* **L2**: PKCE for confidential clients as defense-in-depth.

### V10.3 State Parameter

**V10.3.1 (L1)**: the `state` parameter is generated, sent on authorization request, and verified on callback.

* **Modality**: deterministic.
* **Signal**: state generation uses CSPRNG; callback handler compares received state to the bound session value before exchanging the code.
* **Failure pattern**: state generated but not validated; state set but never compared on callback. This enables CSRF against the OAuth flow.

### V10.4 Redirect URI Validation

**V10.4 (L1)**: the IdP-side redirect URI allow-list is exact-match, no wildcards in path or origin.

* **Modality**: extrinsic for the IdP config (cannot read from repo if IdP is external); deterministic for self-hosted IdP config files.
* **Signal**: client registration / IdP config artifacts.

### V10.5 Token Storage

**V10.5 (L2)**: tokens are not stored in `localStorage` (XSS-readable). Acceptable storage: HttpOnly Secure cookies, in-memory for SPAs paired with refresh-token rotation.

* **Modality**: deterministic.
* **Signal**: `localStorage.setItem('access_token', ...)` or equivalent. Flag.

### V10.6 Resource Server Validation

**V10.6 (L2)**: resource servers validate tokens (V9 applies), check scope claims against the operation, and validate the token's audience matches the resource server.

* **Modality**: hybrid.

---

## Cross-references

* The V8 broken access control prompt template, fully worked: `violations-and-tools.md`.
* JWT algorithm-confusion AST pattern in detail: `violations-and-tools.md`.
* Mappings to NIST IA-2, IA-5, AC-3, IA-11; ISO A.5.15 to A.5.18; SOC 2 CC6.1: `cross-framework.md`.
