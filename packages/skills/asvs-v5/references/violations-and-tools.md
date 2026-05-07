# Violation Patterns and Toolchain Orchestration

This file is the operational manual: real-world failure patterns mapped to ASVS requirements, tool capabilities and gaps, and the agentic prompt templates that bridge the deterministic / semantic boundary.

## Table of contents

1. Tool capability and gap matrix
2. Code-level violation patterns by ASVS chapter
3. Configuration-level violation patterns
4. Dependency-level violation patterns
5. Agentic prompt templates (worked examples)
6. Orchestration recipes (CI/CD wiring)

---

## 1. Tool capability and gap matrix

### Semgrep (Community Edition)

* **Strengths**: 35+ languages; 4,000+ community rules tagged to OWASP Top 10 2025; semantic pattern matching beyond regex; SARIF + JSON output; fast enough for synchronous PR-time gating.
* **Coverage**: V1 (injection sinks), V11 (algorithm strings), V13 (secret patterns), V15 (eval / dangerous APIs), some V3 (header middleware presence), some V9 (JWT library misuse).
* **Gaps**: no deep inter-procedural taint tracking in CE; no policy-document reasoning; no business logic understanding (V2); no IDOR detection (V8). The gap on V2 and V8 is structural, not a bug.
* **When to use**: deterministic phase, primary engine for AST-based checks. Run with `--config "p/owasp-top-ten" --config "p/security-audit"`.

### CodeQL

* **Strengths**: superior taint-tracking accuracy via relational queries over the compiled code-as-database; official curated query suites for high-severity issues; deep cross-procedural analysis where Semgrep CE cannot reach.
* **Coverage**: V1 (deep injection chains), V5 (path traversal across functions), some V8 (where authorization decorators are decorator-pattern enforceable).
* **Gaps**: requires a build for compiled languages (Java, C#, C++, Go); analysis can be slow on large codebases (multi-minute), making synchronous PR gating problematic; cannot read policy documents.
* **When to use**: scheduled deep-scan rather than PR gate, or PR gate only when the diff touches files Semgrep flagged at lower confidence.

### Trivy

* **Strengths**: unified scanner for filesystem, container images, IaC, secrets; high-quality CVE feed; SBOM generation; fast.
* **Coverage**: V13 (SCA, secrets, IaC misconfigurations including TLS settings, encryption flags), V12 (IaC TLS), V14.2 (encryption-at-rest IaC checks), V5.4 (storage bucket public-access flags).
* **Gaps**: no application code analysis; no policy reasoning.
* **When to use**: deterministic phase, IaC + dependencies + secrets in one pass.

### GitLeaks

* **Strengths**: entropy-based + regex-based secret detection across full Git history; `gitleaks protect` for pre-commit; `gitleaks detect` for CI.
* **Coverage**: V13.3, V11.5 (key storage), V9.3 (JWT secret hardcoding).
* **Gaps**: high false-positive rate on test fixtures and example values without disciplined `.gitleaksignore`.
* **When to use**: deterministic phase, run alongside Trivy; differential coverage (Trivy and GitLeaks find slightly different secret patterns).

### OWASP ZAP

* **Strengths**: industry-standard DAST; active scan rules tagged to ASVS; custom scripts in JS/Python/ZEST.
* **Coverage**: runtime aspects of V3 (response headers as observed), V12 (TLS as negotiated), some V4 (API endpoints), some V13 (information disclosure).
* **Gaps**: requires a deployed environment; ZAP's own documentation acknowledges most L2 requirements are not amenable to black-box testing alone; not a repository-only tool.
* **When to use**: post-deploy stage gate, not PR gate. Out of scope for the repository-only scanner this skill primarily describes; mention as the runtime counterpart.

### Custom Semgrep rules

For ASVS requirements with no community rule, write custom rules. Pattern:

```yaml
rules:
  - id: asvs-v9-1-1-jwt-no-algorithm-pin
    languages: [javascript, typescript]
    severity: ERROR
    metadata:
      asvs: V9.1.1
      asvs_level: L1
      cwe: CWE-345
    message: "JWT verification without explicit algorithm pinning. ASVS V9.1.1 requires algorithm pinning to prevent algorithm-confusion attacks."
    pattern-either:
      - pattern: jwt.verify($TOKEN, $KEY)
      - pattern: jwt.verify($TOKEN, $KEY, $OPTS)
    pattern-not: |
      jwt.verify($TOKEN, $KEY, { ..., algorithms: [...], ... })
```

Custom rules should always include `metadata.asvs` so the orchestrator can tag findings without re-mapping.

---

## 2. Code-level violation patterns by ASVS chapter

### V1.2.5 SQL injection

```python
# FAIL
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)

# PASS
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### V1.2.5 OS command injection

```python
# FAIL
subprocess.Popen(f"convert {filename} output.png", shell=True)
os.system("ping " + host)

# PASS
subprocess.run(["convert", filename, "output.png"], check=True)
```

### V1.3 Unsafe deserialization

```python
# FAIL
data = pickle.loads(request.body)
config = yaml.load(uploaded_file)  # default Loader is unsafe

# PASS (signature verification)
verify_hmac(request.body, request.headers["x-signature"])
data = pickle.loads(request.body)

# PASS (safe loader)
config = yaml.safe_load(uploaded_file)
```

### V8.2.1 Broken access control (frontend-only protection)

```javascript
// FAIL: no server-side check
app.post('/api/users/:id/role', (req, res) => {
  db.users.update({ id: req.params.id }, { role: req.body.role });
  res.json({ ok: true });
});

// PASS
app.post('/api/users/:id/role',
  requireAuth,
  requireRole('admin'),
  validateRoleTransition,
  async (req, res) => {
    await db.users.update({ id: req.params.id }, { role: req.body.role });
    audit.log('role_change', { actor: req.user.id, target: req.params.id, role: req.body.role });
    res.json({ ok: true });
  }
);
```

### V8.2.2 IDOR

```javascript
// FAIL: any authenticated user can read any document
app.get('/api/documents/:id', requireAuth, async (req, res) => {
  const doc = await db.documents.findOne({ id: req.params.id });
  res.json(doc);
});

// PASS: scoped query
app.get('/api/documents/:id', requireAuth, async (req, res) => {
  const doc = await db.documents.findOne({
    id: req.params.id,
    ownerId: req.user.id
  });
  if (!doc) return res.status(404).end();
  res.json(doc);
});
```

### V9.1 JWT algorithm-confusion

```javascript
// FAIL: algorithm not pinned
jwt.verify(token, publicKey);  // library may accept HS256 with publicKey as the secret

// FAIL: alg=none accepted
jwt.verify(token, publicKey, { algorithms: ['none'] });

// PASS
jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

### V11.2 Weak cryptography

```java
// FAIL
Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
MessageDigest md = MessageDigest.getInstance("MD5");

// PASS
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
MessageDigest md = MessageDigest.getInstance("SHA-256");
```

### V11.3 Insecure RNG in security context

```javascript
// FAIL
const token = Math.random().toString(36).substring(2);

// PASS
const token = crypto.randomBytes(32).toString('hex');
```

### V15.1 Dynamic code execution

```javascript
// FAIL
setTimeout("doStuff(" + userInput + ")", 100);
new Function('x', userInput)();

// PASS
setTimeout(() => doStuff(safeArg), 100);
```

### V16.2 Sensitive error leakage

```javascript
// FAIL
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.stack });
});

// PASS
app.use((err, req, res, next) => {
  const id = uuid.v4();
  logger.error({ id, err });
  res.status(500).json({ error: 'Internal error', incident_id: id });
});
```

---

## 3. Configuration-level violation patterns

### V3.2 Missing security headers (Express + Helmet)

```javascript
// FAIL
const app = express();
app.use(express.json());
// no helmet, no manual headers

// PASS
const app = express();
app.use(helmet({
  contentSecurityPolicy: { directives: { /* explicit */ } },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));
```

### V3.4 Cookie attributes

```javascript
// FAIL
res.cookie('session', sessionId);
res.cookie('session', sessionId, { secure: false, httpOnly: false });

// PASS
res.cookie('session', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 8 * 60 * 60 * 1000
});
```

### V3.5 CORS misconfiguration

```javascript
// FAIL
app.use(cors({ origin: '*', credentials: true }));  // browser-blocked but indicates misunderstanding

// PASS
app.use(cors({
  origin: ['https://app.example.com', 'https://admin.example.com'],
  credentials: true
}));
```

### V12.1 Kubernetes Ingress without HTTPS redirect

```yaml
# FAIL: no force-ssl-redirect annotation
metadata:
  name: app-ingress

# PASS
metadata:
  name: app-ingress
  annotations:
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
```

### V13.4 Production debug enabled

```python
# FAIL: Django settings.py
DEBUG = True
ALLOWED_HOSTS = ['*']

# PASS
DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', '').split(',')
```

### V14.2 Unencrypted storage (Terraform)

```hcl
# FAIL
resource "aws_db_instance" "primary" {
  storage_encrypted = false
  # or absent (default depends on instance class)
}

# PASS
resource "aws_db_instance" "primary" {
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}
```

---

## 4. Dependency-level violation patterns

* `log4j-core` < 2.17.1 (Log4Shell, CVE-2021-44228 and follow-ons): V13.1 critical.
* `lodash` < 4.17.21 (prototype pollution): V13.1.
* `xz-utils` 5.6.0 / 5.6.1 (CVE-2024-3094 supply-chain backdoor): V13.1.
* `spring-core` versions vulnerable to Spring4Shell (CVE-2022-22965): V13.1.
* `jackson-databind` versions with deserialization gadgets: V1.3 and V13.1.
* `colors.js` and `faker.js` 2022 sabotage: V13.1 (illustrates supply-chain pinning value, V13.2).

Trivy + the OSV database cover these. For organizations on long-term support branches, validate that backports actually patched the issue rather than the version string lying about it.

---

## 5. Agentic prompt templates (worked examples)

### V8.2.1 Broken access control (full template)

```text
SYSTEM:
You are an Application Security Architect verifying OWASP ASVS v5.0.0 Level 2 compliance against an application's Documented Security Decisions.

You will receive:
1. A constraint extracted from docs/security/authorization-policy.md
2. A list of route handlers from src/controllers/
3. A reference to the authorization middleware in src/middleware/

Your task is to determine whether each route enforces the constraint. Output ONLY a JSON array.

Schema:
[
  {
    "route": "<METHOD /path>",
    "asvs_id": "V8.2.1",
    "compliant": true | false | null,
    "evidence_lines": [<int>, ...],
    "policy_clause": "<verbatim quote>",
    "justification": "<one paragraph>",
    "remediation": "<diff or null>"
  }
]

Rules:
- compliant=null means you cannot determine from the provided files. Specify what file you need.
- Frontend hiding of UI elements is NOT compliance. Server-side enforcement is required.
- A scoped database query that filters by ownership IS compliance, even without an explicit middleware.
- Policy must be quoted verbatim, not paraphrased.

USER:
Constraint:
"All endpoints returning user-scoped resources must verify the requesting user's ownership of the resource before serialization. Ownership is established by req.user.id matching the resource.owner_id field, or by a scoped query that filters on owner_id."
Source: docs/security/authorization-policy.md §3.2

Routes:
{enumerated_route_list}

Middleware definitions:
{middleware_file_contents}

Authorization matrix:
{authorization_matrix_csv}
```

### V2 Business logic bypass (template)

```text
SYSTEM:
You are verifying OWASP ASVS v5.0.0 V2.3 (Business Logic Integrity).

You will receive a documented workflow and the controller code that implements it. Determine whether any state-skipping or replay attack is possible.

Output JSON:
{
  "asvs_id": "V2.3",
  "compliant": <bool|null>,
  "attack_paths": [
    {"description": "<text>", "evidence_lines": [<int>, ...]}
  ],
  "remediation": "<text>"
}

Rules:
- A state machine bypass exists if any controller can be invoked in an order other than the documented sequence without a server-side check rejecting the out-of-order call.
- A replay attack exists if a successful operation can be repeated using captured request data with the same effect.

USER:
Documented workflow (from docs/business-logic/checkout.md):
{workflow_text}

Controllers implementing the workflow:
{controller_files}
```

---

## 6. Orchestration recipes

### Minimal CI invocation (GitHub Actions)

```yaml
name: ASVS L2 Audit
on:
  pull_request:
  push:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>  # pin per V13.2
        with: { fetch-depth: 0 }

      - name: Pre-flight (canonical document set)
        run: python scripts/preflight.py

      - name: Semgrep
        run: |
          pip install semgrep
          semgrep scan --config "p/owasp-top-ten" --config ".semgrep/asvs/" \
            --json-output=sast.json --error || true

      - name: Trivy (deps + IaC + secrets)
        run: |
          trivy fs . --format json --output sca.json \
            --scanners vuln,secret,misconfig

      - name: GitLeaks
        run: |
          gitleaks detect --report-path=secrets.json --redact || true

      - name: Synthesize and tag
        run: python scripts/synthesize.py \
          --sast sast.json --sca sca.json --secrets secrets.json \
          --output asvs-report.json

      - name: Agentic phase (V2, V6, V7, V8, V14, V16)
        run: python scripts/agentic.py --report asvs-report.json
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

      - name: Gate
        run: python scripts/gate.py --report asvs-report.json --level L2
```

The pre-flight script halts the job with non-zero exit if the canonical document set is missing. The agentic phase runs only on changes to high-risk paths (auth, session, controllers, middleware, security docs); on documentation-only or test-only diffs, it is skipped.

### Trigger heuristic (excerpt)

```python
HIGH_RISK_PATTERNS = [
    r'.*auth.*', r'.*login.*', r'.*session.*', r'.*token.*',
    r'.*crypto.*', r'controllers/.*', r'middleware/.*',
    r'api/.*', r'docs/security/.*',
]
SUPPRESS_PATTERNS = [
    r'tests/.*', r'__tests__/.*', r'.*\.test\..*',
    r'mocks/.*', r'fixtures/.*', r'vendor/.*',
    r'node_modules/.*', r'\.md$',  # docs-only, except security docs
]

def should_run_agentic(changed_files):
    if any(matches(f, r'docs/security/.*') for f in changed_files):
        return True  # always re-audit on policy change
    risky = [f for f in changed_files if matches_any(f, HIGH_RISK_PATTERNS)]
    risky = [f for f in risky if not matches_any(f, SUPPRESS_PATTERNS)]
    return len(risky) > 0
```

---

## Honest limits revisited

* Semgrep CE on V8 is structurally limited. The agent does the V8 work. Do not pretend Semgrep covers IDOR; it does not.
* CodeQL on languages requiring a build is blocked by repos that do not build cleanly under default settings. Falling back to Semgrep + agentic is acceptable; document the fallback in the report.
* The agentic phase is the slowest and most expensive. Trigger heuristics matter for cost and developer velocity. Tune them.
* Some violations only appear at runtime (rate limiting effectiveness, lockout behavior, WAF rules, runtime CSP enforcement). Pair with ZAP post-deploy.
