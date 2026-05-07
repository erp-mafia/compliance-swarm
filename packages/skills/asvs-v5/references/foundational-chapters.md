# ASVS v5.0.0 Chapters V1 through V5: Foundational and Data Handling

Detailed catalog for the foundational chapters governing ingestion, processing, and display of data. Load this file when working on injection prevention, validation, frontend security, API surface, or file handling.

Each requirement entry lists: ID, level, modality, signal/AST pattern, false-positive traps.

---

## V1: Encoding and Sanitization

Defines the architecture for decoding and unescaping data, injection prevention, safe deserialization, and memory management.

### V1.1 Encoding Architecture (documentation prerequisite)

**V1.1.x**: the team must produce an encoding architecture document. The agent reads this first; downstream V1 checks validate against it.

* **Modality**: agentic.
* **Signal**: presence of `docs/security/encoding-architecture.md` (or equivalent) listing per-context output encoding rules (HTML body, HTML attribute, JS context, CSS context, URL, JSON, XML).
* **Failure**: document missing. Halt V1 verification.

### V1.2 Injection Prevention

**V1.2.5 (L1)**: SQL queries use parameterized bindings.

* **Modality**: deterministic.
* **AST signal**: SQL execution sinks (`.execute`, `.query`, `cursor.execute`) where the SQL string contains string interpolation, `+`, f-string, or template literal of a tainted variable.
* **False positives**: ORM `.where(raw(...))` calls where the raw fragment is a static literal. Schema migration files. Test fixtures.
* **Cross-framework**: NIST SI-10, CIS 16.10, ISO A.8.26.

**V1.2.5 (L1)**: OS command injection.

* **Modality**: deterministic.
* **AST signal**: `subprocess.Popen(..., shell=True)` with non-literal first argument; `os.system(...)`, `child_process.exec(...)`, Java `Runtime.getRuntime().exec(stringConcat)`, Ruby backticks with interpolation.
* **Safe pattern**: argument-array form (`subprocess.run([cmd, arg1, arg2], shell=False)`).
* **False positives**: shell strings built entirely from constants and environment variables that are themselves not user-tainted.

**V1.2 (L2)**: NoSQL injection (Mongo `$where`, dynamic JS evaluation).

* **Modality**: deterministic.
* **AST signal**: Mongo queries using `$where` with non-literal payload; `eval`-style operators receiving request data.

**V1.2 (L2)**: LDAP injection, XPath injection, SSRF via unvalidated outbound URL.

* **Modality**: deterministic for sink detection, agentic for whether the sink is on a trusted path.
* **Signal**: HTTP client invocation (`fetch`, `axios`, `requests.get`, `http.Client`) with URL constructed from request input and no allow-list check upstream.

### V1.3 Safe Deserialization

**V1.3 (L1)**: deserialization sinks must validate provenance before object reconstruction.

* **Modality**: deterministic.
* **Signal**: Java `ObjectInputStream.readObject()`, Python `pickle.loads`, Python `yaml.load` without `SafeLoader`, PHP `unserialize`, .NET `BinaryFormatter`. Each call must be preceded by a cryptographic signature verification or operate over a known-trusted source (filesystem under app control).
* **Hard failure**: `BinaryFormatter` is deprecated and unsafe under any circumstance; flag unconditionally.

### V1.4 Memory Safety (C/C++ scope)

**V1.4 (L2)**: bounds-checked memory operations.

* **Modality**: deterministic.
* **Signal**: `strcpy`, `strcat`, `sprintf`, `gets` in C/C++. Recommend `strncpy_s`, `snprintf`, fmtlib.

---

## V2: Validation and Business Logic

Robust input validation, anti-automation, and protection of logical workflows against circumvention.

### V2.1 Validation Architecture (documentation prerequisite)

* **Modality**: agentic.
* **Signal**: documented validation strategy: where validation runs (edge, controller, domain), what the trust boundary is, whether server-side validation is mandatory after any client-side check.
* **Failure**: document missing.

### V2.2 Centralized Validation

**V2.2 (L2)**: validation lives in declarative middleware, not scattered ad-hoc checks.

* **Modality**: hybrid. SAST detects schema validators (Joi, Zod, Pydantic, Bean Validation, FluentValidation). Agent verifies every controller is covered.
* **Signal (deterministic)**: presence of validation middleware on routes; absence of `req.body` direct access bypassing validation.

### V2.3 Business Logic Integrity

**V2.3 (L2)**: state machines cannot be bypassed by skipping steps.

* **Modality**: agentic.
* **Signal**: the agent reads the documented business workflow, then traces controllers to verify state transitions check prior state. Common failure: `POST /checkout/finalize` does not verify `cart.state === 'PAYMENT_VERIFIED'`.
* **False positives**: legitimate admin override paths. The agent must read the policy to distinguish.

### V2.4 Anti-Automation

**V2.4 (L2)**: anti-automation controls on credential, registration, and high-value endpoints.

* **Modality**: hybrid. Deterministic detection of rate-limit middleware, CAPTCHA invocation, lockout configuration. Runtime effectiveness is extrinsic (DAST or production telemetry).
* **Signal**: rate-limit annotations or middleware on `/login`, `/register`, `/forgot-password`, payment endpoints.

---

## V3: Web Frontend Security (new in v5.0.0)

Browser-side protections, CSP, secure cookies, origin separation, external resource integrity.

### V3.1 Frontend Security Decisions (documentation prerequisite)

Required: CSP policy, cookie strategy, framing strategy, COOP/COEP/CORP posture, third-party script inventory.

### V3.2 HTTP Security Headers

**V3.2 (L1)**: security headers present.

* **Modality**: deterministic.
* **Signal**: configuration parsing of Nginx/Apache/middleware (Helmet for Express, Spring Security headers, ASP.NET headers middleware). Required: `Strict-Transport-Security` (with `max-age >= 31536000`, `includeSubDomains`), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Content-Security-Policy`.
* **False positives**: dev-only configs not deployed; check the production config path.

### V3.3 Content Security Policy

**V3.3 (L2)**: CSP without `unsafe-inline` or `unsafe-eval` in script-src.

* **Modality**: deterministic with caveats.
* **Signal**: parse the `Content-Security-Policy` header. Flag `unsafe-inline`, `unsafe-eval`, wildcard `*` in `script-src` or `default-src`. Hashes and nonces are acceptable.

### V3.4 Cookie Attributes

**V3.4 (L1)**: session cookies have `HttpOnly`, `Secure`, `SameSite=Lax` or stricter.

* **Modality**: deterministic.
* **Signal**: cookie configuration in session middleware, framework session config, or `Set-Cookie` literal strings. Flag missing `HttpOnly`, missing `Secure`, `SameSite=None` without `Secure`.

### V3.5 CORS

**V3.5 (L2)**: CORS does not combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Origin allow-lists are explicit, not wildcarded for authenticated endpoints.

* **Modality**: deterministic.
* **Signal**: CORS middleware config. The `*` + `credentials: true` combination is browser-blocked but indicates a fundamental misunderstanding; flag aggressively.

---

## V4: API and Web Service

REST, GraphQL, WebSocket message structure validation; generic web service security.

### V4.1 API Surface Documentation (prerequisite)

* **Signal**: `openapi.yaml` / `swagger.json` / `schema.graphql` present. Agent uses these to enumerate the attack surface.

### V4.2 Schema Validation

**V4.2 (L1)**: requests validate against the published schema.

* **Modality**: deterministic.
* **Signal**: schema-validating middleware (`express-openapi-validator`, `connexion`, Spring `@Valid`, FastAPI Pydantic models).

### V4.3 GraphQL Specifics

**V4.3 (L2)**: query depth and complexity limits; introspection disabled in production.

* **Modality**: deterministic.
* **Signal**: presence of depth-limit / complexity-limit plugins (`graphql-depth-limit`, `graphql-cost-analysis`). Production config sets `introspection: false`.

### V4.4 WebSocket

**V4.4 (L2)**: WebSocket message handlers validate state and authorization on every message, not only at handshake.

* **Modality**: agentic.
* **Signal**: agent reads handler functions, checks for per-message auth or state validation. Common failure: handshake-only auth allows a hijacked connection to issue privileged messages indefinitely.

### V4.5 Mass Assignment

**V4.5 (L2)**: object updates use allow-list field binding, not whole-object hydration from request body.

* **Modality**: hybrid.
* **Signal**: `User.update(req.body)` patterns; absence of `pick`/`omit`/DTO mapping. Especially dangerous on user/role objects where a client-supplied `role: 'admin'` in body bypasses authorization.

---

## V5: File Handling

Upload processing, content inspection, storage isolation, safe download delivery.

### V5.1 File Handling Decisions (prerequisite)

Required: allowed types, size limits, storage location, virus scan policy, serving strategy (direct / proxied / signed URL).

### V5.2 Upload Validation

**V5.2 (L1)**: file uploads validate content type by inspection, not extension or `Content-Type` header alone.

* **Modality**: deterministic.
* **Signal**: presence of magic-number check (`file-type` / `python-magic` / Apache Tika). Flag uploads accepted on `req.file.mimetype` alone.

### V5.3 Path Traversal

**V5.3 (L1)**: filesystem paths constructed from upload metadata are sandboxed.

* **Modality**: deterministic.
* **Signal**: `path.join(uploadDir, req.body.filename)` or equivalent without normalization. Required: canonicalize and verify resulting path remains within `uploadDir`. Flag `../` permitted in resolved path.

### V5.4 Storage Isolation

**V5.4 (L2)**: uploaded files served from a domain or path that does not execute server-side code.

* **Modality**: hybrid.
* **Signal (deterministic)**: cloud storage IaC. Bucket has `block_public_acls = true`, `block_public_policy = true`, encryption at rest, no public list permission. Bucket policy denies execution of uploaded content (no Lambda triggers on user uploads without signature).
* **Common failure**: uploads served from `/uploads/` under the application origin, allowing stored XSS or HTML smuggling.

### V5.5 Antivirus / Content Scan

**V5.5 (L2)**: malware scanning on accepted uploads.

* **Modality**: agentic for whether scan occurs before user-visible storage; deterministic for the presence of a scanner integration (ClamAV, S3 + GuardDuty Malware Protection, third-party API).

---

## Cross-references

* For agentic prompt templates against V2 (business logic) and V8 (authorization): `violations-and-tools.md`.
* For NIST/CIS/ISO/SOC 2 mappings of these requirements: `cross-framework.md`.
* For canonical document file paths the pre-flight searches: `canonical-documents.md`.
