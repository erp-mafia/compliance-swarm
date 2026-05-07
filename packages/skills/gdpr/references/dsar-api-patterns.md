# DSAR API Patterns

Articles 15-22 require the data controller to fulfill data subject requests within 30 days (Article 12(3), extendable by two months for complex cases). The scanner verifies that the repository implements specific endpoint patterns and that the OpenAPI contracts enforce purpose limitation.

## Required endpoints

The agent searches for endpoints satisfying the access (Art. 15), erasure (Art. 17), and portability (Art. 20) rights. Rectification (Art. 16) is typically satisfied through the existing user-profile-update endpoint and is verified differently. Restriction (Art. 18) and objection (Art. 21) usually correspond to flag-flip operations on processing consent.

### Access (Art. 15)

```
GET /api/v1/privacy/user/data
Authorization: Bearer <subject_token>
Accept: application/json
```

**Behavior**: aggregates and returns a unified profile of all personal data the controller holds about the requesting subject across the entire microservice architecture.

**Verification rules**:
* The endpoint exists and is registered in the OpenAPI spec.
* The controller method invokes a documented aggregation function (not a single-table query).
* Response schema includes every Fideslang `data_category` documented in `.compliance/ropa.yaml` for the subject's category.
* Identity verification beyond the API auth layer is documented in `.compliance/dsar_runbook.md` (proof-of-identity requirement, since a stolen access token must not enable a full data dump).

### Erasure (Art. 17)

```
DELETE /api/v1/privacy/user/data
Authorization: Bearer <subject_token>
```

**Behavior**: triggers irreversible deletion or cryptographic shredding across all data stores. Returns a job identifier for asynchronous processing tracking.

**Verification rules** (the highest-frequency violation site):
* The handler does NOT execute `UPDATE ... SET is_deleted = true` (or equivalent ORM soft-delete). The agent traces the controller statically.
* The handler invokes a documented hard-delete or cryptographic-shredding function on each data store enumerated in the RoPA.
* Legitimate retention overrides (tax law, AML) are documented in the DPIA or RoPA, with the specific fields and retention bases enumerated. The handler honors these overrides via specific conditional logic (not a general soft-delete fallback).
* The job state is auditable and the controller can demonstrate completion within 30 days.

### Portability (Art. 20)

```
GET /api/v1/privacy/user/export
Authorization: Bearer <subject_token>
Accept: application/json | text/csv
```

**Behavior**: serializes the subject's data into a structured, commonly used, machine-readable format. JSON or CSV are the typical defaults; XML or other open formats are also acceptable.

**Verification rules**:
* The response is structured (not a PDF or HTML rendering of profile data).
* The schema is the same shape as Article 15 for the data the subject provided to the controller (Article 20(1) is narrower in scope than Article 15; only data the subject has provided is portable).

### Rectification (Art. 16)

Typically the existing `PUT /api/v1/users/me` or equivalent. The verification check is that the same endpoint also exists for non-self-service modifications when the subject's request must be processed asynchronously.

### Restriction and objection (Art. 18, Art. 21)

```
POST /api/v1/privacy/user/restrict
POST /api/v1/privacy/user/object
```

**Behavior**: flag-flip operations that alter downstream processing. The verification check is that the flag is *honored* by the relevant processing operations - the agent traces from the flag store to the processing operations registered against it in the RoPA.

## OpenAPI Schema validation

Purpose limitation (Article 5(1)(b)) is mechanically enforceable through schema validation. Two rules:

### `additionalProperties: false`

Every data-ingestion request schema must set `additionalProperties: false`. Without it, the schema admits unbounded extraneous fields that bypass the data minimization principle.

```yaml
components:
  schemas:
    CreateUserRequest:
      type: object
      additionalProperties: false       # required
      required: [email, locale]
      properties:
        email: { type: string, format: email, x-fideslang: "user.contact.email" }
        locale: { type: string, x-fideslang: "user.preferences" }
```

### Fideslang annotation alignment with declared scope

The agent reads the OAuth scope required by the endpoint (e.g., `customer_support`) and validates against the response schema's Fideslang annotations. An endpoint scoped `customer_support` must not return fields annotated `user.payment.credit_card_number` or `user.behavior.browsing_history` - those scopes are not commensurate with customer support purposes.

## RBAC and identity verification

DSAR endpoints are high-value targets. An attacker with a stolen access token effectively has the keys to a complete data dump. Two layers of defense are required:

### API-layer authentication

OAuth 2.0 or OpenID Connect with strict scope. The token must carry a scope specific to DSAR operations (e.g., `dsar:self`); a general `user` scope is insufficient.

### Identity proofing

The DSAR runbook documents a proof-of-identity step beyond the access token. Common patterns:
* Email-link confirmation to the registered address with a short TTL
* Multi-factor reauthentication
* Knowledge-based verification questions (less preferred)
* For high-sensitivity contexts, a manual review step

The agent verifies that the runbook documents this and that the endpoint's controller logic invokes the documented verification function.

## Third-party PII redaction

Article 15(4) limits the right of access to the extent that providing data would adversely affect the rights and freedoms of others. In practice: a chat log including messages from other users, a shared document with co-author identities, an organization context with peer information.

The agent verifies that the response builder for `GET /api/v1/privacy/user/data` invokes a documented redaction function over fields that may contain third-party PII. The redaction function must:

* Replace direct identifiers (other users' names, email addresses) with anonymous placeholders
* Strip metadata that could re-identify the third party (user IDs, session IDs)
* Preserve the structural relationship for the requesting subject's understanding (so a chat log remains coherent without naming the other party)

The check is partly Tier 1 (the function exists and is invoked) and partly Tier 2 (the redaction is sufficient given the actual third-party data shapes in scope).

## Asynchronous job tracking

Erasure and large-scale exports cannot complete synchronously. The agent verifies the existence of:

* A job creation endpoint that returns a job identifier
* A status endpoint to poll job completion
* A retention period for the job artifact (export downloads must expire; the export file itself is sensitive PII)
* An audit log of job initiation, progression, and completion, with each entry tied to the requesting subject

## Idempotency and replay

DSAR endpoints should be idempotent at the request level. A subject who issues an erasure request twice in error should not have the request re-queued or duplicated. The agent checks for an idempotency key pattern in the controller, typically a request ID or a content-derived hash.

## Common failure modes by article

| Article | Common DSAR endpoint failure |
|---------|------------------------------|
| Art. 15 | Endpoint returns only the primary user table; misses records in event store, analytics warehouse, message queues, third-party processors |
| Art. 17 | Soft-delete masquerading as erasure |
| Art. 17 | Backups not addressed; deleted data remains recoverable indefinitely |
| Art. 20 | Format is not machine-readable (PDF), or limited to data the controller derived rather than data the subject provided |
| Art. 18 | Flag flipped but downstream processors do not consult the flag |
| Art. 21 | Marketing systems not wired to the objection flag; opt-out is not honored |

The scanner should emit specific findings against each of these patterns when detected.