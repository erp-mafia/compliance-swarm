# Violation Patterns

Real-world heuristics for the scanner. Each pattern below is drawn either from a regulatory enforcement action, an architectural failure mode documented in the GDPR-Bench-Android study, or a publicly disclosed supply chain incident. The agent should treat these as concrete detection targets rather than abstract guidelines.

## Code-level anti-patterns

### Sensitive API access without consent gate (Art. 6)

**Pattern**: invocation of camera, microphone, geolocation, contacts, or biometric APIs without a preceding conditional checking the documented consent state.

**Android example** (from the source document):
```java
manager.openCamera(cameraId, stateCallback, null);  // no consent check
```

**Detection**: AST scan for the sensitive API surface (per platform: `android.hardware.camera2`, `CoreLocation`, `navigator.geolocation`, `MediaDevices.getUserMedia`), then walk up the control flow graph looking for a guard against a consent provider. Absence of the guard is the finding.

**Why it lands as Article 6**: any processing operation needs a lawful basis. For sensor APIs in a consumer context, the basis is almost always consent (Art. 6(1)(a)). Capturing without checking the consent state means processing without lawful basis.

### Unsafe logging of PII (Art. 32, Art. 5(1)(f))

**Pattern**: stack traces, request bodies, or full user objects written to standard output, log files, or third-party log aggregators.

**Examples**:
```javascript
console.log(userObject);                              // Node.js
logger.info("Failed login for " + email);             // Java/Python
fmt.Printf("%+v\n", request)                          // Go, with PII in request
```

**Detection**: Semgrep rules for `console.log`, `logger.*`, `print` calls whose arguments resolve to variables flagged by Privado as containing PII.

**Operational nuance**: distinguishing safe logging (log a request ID, not a request body) from unsafe logging is exactly the kind of check where deterministic AST analysis underperforms LLM analysis. The skill should run a Semgrep first pass for the obviously bad patterns, then escalate ambiguous cases to the agentic auditor.

### Inadequate Article 17 erasure

**Pattern**: the endpoint registered to satisfy the right to erasure performs a soft-delete (boolean flag, status enum change, timestamp on a `deleted_at` column) rather than hard deletion or cryptographic shredding.

**Detection**: identify the erasure endpoint via:
* OpenAPI tag `dsar` or `privacy`
* Convention paths (`/api/.*privacy.*delete`, `/api/.*forget`)
* DSAR runbook reference

Then trace the controller method statically. Any path that reaches a SQL `UPDATE` (or ORM `update()`) instead of `DELETE` (or a documented anonymization function) is the finding.

**Edge case**: legitimate retention obligations (tax law, anti-money-laundering) may legally override the right to erasure for specific fields. The DPIA or RoPA should document this; the scanner should escalate to the agentic auditor when it detects soft-delete patterns to check for a documented retention basis rather than auto-flagging.

### Plaintext PII in error responses (Art. 32)

**Pattern**: API error handlers reflecting PII back to the caller in error messages or stack traces.

```python
@app.errorhandler(500)
def handle_500(e):
    return {"error": str(e), "context": request.json}, 500   # leaks PII
```

**Detection**: Semgrep on error handler bodies that reference request bodies, query parameters, or session objects.

## Configuration-level anti-patterns

### Overly permissive CORS (Art. 25, Art. 32)

**Pattern**: `Access-Control-Allow-Origin: *` on endpoints serving authenticated PII; `Access-Control-Allow-Credentials: true` paired with permissive origins.

**Detection**: parse middleware configuration (Express, FastAPI, Spring), API gateway resource policies, and CDN configurations. Cross-reference with the endpoint inventory; permissive CORS on a public marketing endpoint is fine, on `/api/v1/users/me` it is not.

### Mobile permission overreach (Art. 5(1)(c))

**Pattern**: `AndroidManifest.xml` requesting `ACCESS_FINE_LOCATION`, `READ_CONTACTS`, `READ_SMS`, `RECORD_AUDIO`, `CAMERA` when the app's documented purposes do not require them. iOS equivalent: `Info.plist` `NS*UsageDescription` keys.

**Detection**: enumerate requested permissions, cross-reference each against the Fideslang `data_categories` documented in `.compliance/ropa.yaml`. An app that lists no `user.location` data category in the RoPA but requests `ACCESS_FINE_LOCATION` is flagged.

### Disabled or missing security headers (Art. 32)

**Pattern**: web server configurations missing `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options`, or `Referrer-Policy`.

**Detection**: parse Nginx, Apache, Caddy, Cloudflare, AWS CloudFront, or framework-level header configurations. Check for the canonical set; emit findings per missing header.

## Dependency and supply chain risks

### Invasive third-party SDKs

**Pattern**: presence of advertising or analytics SDKs known for covert tracking or device fingerprinting without valid consent.

**Regulatory anchors**:
* CNIL fined Apple and Voodoo Games in 2023 over advertising identifier use without adequate consent
* CNIL fined Clearview AI repeatedly for non-compliant biometric scraping
* IMY (Sweden) has issued multiple decisions on Google Analytics post-Schrems II

**Detection**: maintain a denylist of SDK package coordinates (e.g., `com.facebook.android:facebook-android-sdk` for advertising-grade fingerprinting, specific MMP SDKs, ad-tech identifiers). Match against `package.json`, `build.gradle`, `Podfile`, etc. Presence requires Tier 2 escalation to verify consent gating.

### Compromised OAuth integrations

**Pattern**: outdated authentication libraries or OAuth client implementations vulnerable to known account takeover patterns.

**Reference incident**: the SalesLoft / Drift supply chain compromise demonstrated that OAuth tokens leaked through an integrated tool propagated to dozens of downstream Salesforce instances, each constituting an Article 32 confidentiality breach.

**Detection**: SCA tools (Snyk, Dependabot, Trivy, Grype) cross-referenced with NVD CVE data for OAuth, SAML, and session-management libraries. Combine with secret scanning for committed OAuth refresh tokens and client secrets.

### Transitive dependency backdoors

**Pattern**: deeply nested dependencies containing data-harvesting code that exfiltrates environment variables, secrets, or PII to external servers.

**Reference incident**: the Shai-Hulud npm backdoor pattern, where compromised packages walked the environment looking for credentials and posted them to attacker-controlled hosts.

**Detection**: SCA combined with malware scanners (Phylum, Socket, Snyk Malicious Packages). The scanner should inspect not just direct dependencies but the full transitive closure, with particular attention to recently published versions of long-lived packages and to packages with low download counts being added near production paths.

### Customer management system exposure

**Pattern**: customer-facing applications with exposed administrative interfaces, weak authentication on internal CRMs, or insecure data export endpoints.

**Reference incident**: the Italian Garante fined Enel substantially for failing to secure a customer management system that enabled unauthorized data acquisition by third parties.

**Detection**: out-of-band, requires DAST (dynamic application security testing). The static scanner can verify that admin routes have RBAC middleware applied; it cannot verify that the RBAC is correctly enforced at runtime without DAST.

## Combining patterns into severity

A single low-severity finding rarely justifies blocking a deployment. Combinations do:

* **Critical (block)**: hardcoded production credentials + plaintext PII transmission. The combined exposure is multiplicative.
* **Critical (block)**: special category data (Art. 9) + missing encryption at rest + non-EEA data sink. Three-way violation: Art. 9(2) basis missing, Art. 32 inadequate, Art. 44 transfer inadequate.
* **High (warn)**: invasive SDK present + no consent gating + frontend tracker initializes pre-consent. Defer to agentic Tier 2 to confirm before blocking.
* **Medium (warn)**: missing security header + cookie tagged as analytics without consent flow.

The agent should compute these combinations rather than emitting each finding in isolation. The blast radius of compounded violations is what regulators actually fine on.