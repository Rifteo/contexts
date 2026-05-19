---
name: code-audit
l0: Source code audit — quality, architecture, maintainability, and security. Every finding requires evidence.
license: MIT
metadata:
  version: "0.0.1"
  author: AuditGuard
  tags: ["code-review", "sast", "static-analysis", "secure-coding", "architecture", "maintainability", "code-quality"]
---

## L1 — Overview

A code audit reviews source code across four dimensions: quality, architecture, maintainability, and security. It combines manual review with static analysis tooling across the full codebase or a targeted module.

**Use this context when:**
- Reviewing a codebase for security vulnerabilities, design issues, or quality problems
- Auditing a pull request or feature branch before merge
- Assessing a third-party or open-source component
- Performing a pre-release or compliance-driven review
- Investigating a suspected vulnerability or systemic code problem

**Key focus areas:** Authentication and authorization logic, input validation, secrets in code, cryptography misuse, dependency vulnerabilities, error handling, injection sinks, insecure deserialization, race conditions, coupling, cohesion, complexity, naming, test coverage.

---

## Finding Types

Every finding must be assigned exactly one of these four types:

### Code Quality
Issues that degrade the correctness, reliability, or robustness of the code at the implementation level.

**Examples:** dead code that masks bugs, off-by-one errors, unchecked return values, improper null handling, misused APIs, logic errors, duplicated logic with divergent behavior.

### Code Architecture
Issues that reflect flawed structural or design decisions across modules, layers, or services.

**Examples:** circular dependencies, wrong layer handling business logic (e.g., SQL in controllers), missing abstraction boundaries, tight coupling between unrelated components, God objects, violating separation of concerns.

### Code Maintainability
Issues that make the code difficult to understand, modify, test, or extend safely over time.

**Examples:** excessive cyclomatic complexity, inconsistent naming conventions, missing or misleading documentation for non-obvious logic, magic numbers, deep nesting, untestable code, large functions/classes, missing error context.

### Code Security
Issues that introduce an exploitable vulnerability or weaken the security posture.

**Examples:** injection sinks, hardcoded secrets, broken authentication, insecure crypto, IDOR, missing authorization checks, unsafe deserialization, information disclosure in error responses, vulnerable dependencies.

---

## L2 — Full Methodology

### Phase 1 — Scope and Setup

- Identify the languages, frameworks, and build system in use
- Locate entry points: HTTP handlers, CLI argument parsers, message queue consumers, file parsers
- Map trust boundaries: what data comes from users, external services, or environment variables
- Clone the repo and run the build to confirm the code is in a known-good state
- Collect architecture diagrams, prior audit records, and compliance requirements if available
- Run automated scanners first — manual review fills the gaps they miss

**Reviewer discipline:**
- Limit review sessions to 60–90 minutes — attention degrades sharply beyond that
- Review no more than 400–500 lines of code per session; defect detection drops beyond this
- Use risk-based prioritization: focus first on authentication, payment, data handling, and public-facing entry points
- Assign domain-knowledgeable reviewers to business-logic-heavy modules

**Automated scanners by language:**

| Language | Tool |
|---|---|
| Python | `bandit`, `semgrep` |
| JavaScript/TypeScript | `eslint-plugin-security`, `semgrep`, `njsscan` |
| Java | `SpotBugs + FindSecBugs`, `semgrep` |
| Go | `gosec`, `semgrep` |
| Ruby | `brakeman` |
| PHP | `phpcs-security-audit`, `semgrep` |
| Any | `semgrep --config=p/security-audit` |
| Any (quality) | `SonarQube`, `SonarCloud` |

```bash
# Run semgrep across the repo
semgrep --config=p/security-audit --config=p/secrets .

# Run Gitleaks for secrets in git history
gitleaks detect --source . --report-format json --report-path gitleaks.json
```

---

### Phase 1b — Threat Modeling

Threat modeling identifies design-level vulnerabilities before a single line of code is read. It prevents wasted time on code-level findings that stem from a fundamentally flawed design.

**When to run:** Before detailed code review, especially for authentication, payment, or data-handling modules.

**Methodology (STRIDE):**

| Threat | Targets | Example |
|---|---|---|
| **S**poofing | Authentication | Attacker impersonates another user |
| **T**ampering | Integrity | Attacker modifies data in transit or storage |
| **R**epudiation | Logging | Action taken with no audit trail |
| **I**nformation Disclosure | Confidentiality | Sensitive data leaked in error responses |
| **D**enial of Service | Availability | Request flood exhausts DB connections |
| **E**levation of Privilege | Authorization | Low-privilege user accesses admin functions |

**Steps:**
1. Draw a data flow diagram (DFD) — identify all processes, data stores, external entities, and data flows
2. Mark trust boundaries on the DFD (e.g., user-facing vs. internal network vs. DB)
3. Apply STRIDE to each element — enumerate threats per trust boundary crossing
4. Prioritize threats by likelihood × impact before starting code review
5. Use identified threats as a checklist during Phases 3–8

---

### Phase 2 — Secrets and Credentials

Look for hardcoded secrets, credentials, and keys in source code and git history.

**Manual patterns to grep for:**
```bash
grep -rn "password\s*=" .
grep -rn "api_key\s*=" .
grep -rn "secret\s*=" .
grep -rn "BEGIN RSA PRIVATE KEY" .
grep -rn "AKIA[0-9A-Z]{16}" .   # AWS access keys
grep -rn "sk-[a-zA-Z0-9]{32,}" . # OpenAI keys
```

**Check git history:**
```bash
git log -p | grep -i "password\|secret\|api_key\|token" | head -100
gitleaks detect --source . --log-opts="--all"
```

**What to flag:**
- Hardcoded credentials committed to any branch (even old commits)
- Secrets in config files committed without `.gitignore` protection
- Environment variable values hardcoded as fallbacks: `os.getenv("SECRET", "fallback-value")`
- Private keys or certificates in the repository

---

### Phase 3 — Authentication, Authorization, and Business Logic

Review code that enforces identity, access control, and application-specific rules — this is where high-severity findings cluster and where automation is weakest.

**Authentication review:**
- Is password hashing using a slow algorithm? (`bcrypt`, `argon2`, `scrypt` — not `md5`, `sha1`, `sha256`)
- Is session token generation cryptographically random? (`secrets.token_hex()`, `crypto.randomBytes()` — not `Math.random()`)
- Are JWT tokens validated? Check that signature is verified, `alg: none` is rejected, and expiry is enforced
- Is MFA enforced on sensitive operations?
- Are failed login attempts rate-limited?

**Authorization review:**
- Trace every privileged operation back to an authorization check
- Look for checks done only on the frontend (JS) with no server-side enforcement
- Verify that role checks happen before data is returned — not just before it is rendered
- Check for IDOR: are object IDs validated against the requesting user's ownership?

```python
# Red flag — no ownership check before returning data
def get_document(doc_id):
    return db.query("SELECT * FROM docs WHERE id = ?", doc_id)

# Correct
def get_document(doc_id, user_id):
    return db.query("SELECT * FROM docs WHERE id = ? AND owner_id = ?", doc_id, user_id)
```

**Business logic review (manual only — scanners cannot detect these):**
- Are multi-step workflows (checkout, approval, password reset) completable out of order?
- Are numeric limits enforced server-side? (e.g., negative quantities, price overrides, discount stacking)
- Can a user skip required states in a state machine? (e.g., bypass payment step to reach confirmation)
- Are concurrent requests to the same operation idempotent, or can they cause double-execution?
- Are privilege escalation paths possible through role or account manipulation?
- Can a low-privilege user trigger high-privilege background jobs by crafting specific inputs?

---

### Phase 4 — Input Validation and Injection Sinks

Trace user-controlled data from entry points to dangerous sinks.

**Entry points (sources):**
- HTTP parameters, headers, body, cookies
- File uploads and filenames
- CLI arguments and environment variables
- Data read from files, databases, or message queues

**Dangerous sinks:**
- SQL queries — look for string concatenation instead of parameterized queries
- Shell commands — `os.system()`, `subprocess(shell=True)`, `exec()`, `eval()`
- Template rendering — unsanitized user input passed to template engines
- File paths — user-controlled paths without sanitization (`../` traversal)
- HTML output — user data rendered without escaping (XSS)
- Deserialization — `pickle.loads()`, `yaml.load()` (not `safe_load`), Java `ObjectInputStream`

```python
# SQLi — flag this
query = "SELECT * FROM users WHERE name = '" + username + "'"

# Command injection — flag this
os.system("ping " + user_input)

# Unsafe deserialization — flag this
obj = pickle.loads(request.body)
```

---

### Phase 5 — Cryptography Review

- Are deprecated algorithms in use? (`MD5`, `SHA1`, `DES`, `RC4`, `ECB` mode)
- Are keys and IVs generated randomly per operation, or reused?
- Is TLS enforced for all external connections? Are certificate errors suppressed?
- Are random values used for security (tokens, nonces) using a CSPRNG?
- Is sensitive data encrypted at rest? What key management is in place?

```python
# Weak — flag
hashlib.md5(password.encode()).hexdigest()

# Insecure random — flag
import random; token = random.randint(0, 999999)

# Correct
import secrets; token = secrets.token_hex(32)
```

---

### Phase 6 — Error Handling and Logging

- Do error responses leak stack traces, internal paths, SQL queries, or version strings to the client?
- Are exceptions caught too broadly, masking real errors silently?
- Is sensitive data (passwords, tokens, PII) written to logs?
- Are logs structured and tamper-evident, or plain text and easily forged?

```python
# Leaks internals — flag
except Exception as e:
    return {"error": str(e), "traceback": traceback.format_exc()}

# Logs sensitive data — flag
logger.info(f"User login: {username} password={password}")
```

---

### Phase 7 — Dependency and Supply Chain Review

- List all direct and transitive dependencies (80–90% of application code typically comes from dependencies)
- Check for known CVEs: `pip-audit`, `npm audit`, `trivy`, `grype`, `snyk`
- Look for typosquatted or suspicious package names
- Check for pinned versions vs. floating ranges (`>=1.0` is a risk)
- Review any packages fetched from non-registry sources (git URLs, local paths)
- Check for reachability: does the vulnerable function in a flagged dependency actually get called? (reduces false positives by up to 95%)

```bash
# Python
pip-audit

# Node.js
npm audit --audit-level=high

# Any language (container or filesystem)
grype dir:.
trivy fs .

# Generate a Software Bill of Materials (SBOM)
syft dir:. -o cyclonedx-json > sbom.json

# Continuously audit the SBOM against known CVEs
# Use Dependency-Track (self-hosted) or upload sbom.json to a SCA platform
```

**License compliance:**
- Flag dependencies with GPL, AGPL, or SSPL licenses in commercial/proprietary codebases — these can trigger copyleft obligations
- Flag dependencies with no clear license (unlicensed code cannot legally be used in many contexts)
- Tools: `liccheck` (Python), `license-checker` (Node.js), `trivy --scanners license`

```bash
# Python license check
pip install liccheck && liccheck

# Node.js license check
npx license-checker --summary
```

---

### Phase 8 — Race Conditions and State Management

- Are shared resources (files, DB rows, in-memory counters) accessed without locks?
- Are TOCTOU (time-of-check-time-of-use) patterns present? (check a condition, then act — gap between the two)
- Are financial or inventory operations protected against double-spend or concurrent modification?

```python
# TOCTOU — flag
if not os.path.exists(filename):   # check
    open(filename, 'w').write(data) # use — race window here
```

---

### Phase 9 — Code Quality Metrics

Measure implementation-level quality using objective metrics. Flag anything outside acceptable thresholds as a `Code Quality` or `Code Maintainability` finding.

**Complexity:**
- **Cyclomatic complexity** — number of independent paths through a function. Target: <10 per method. Flag >20 as high, flag 10–20 as medium.
- **Cognitive complexity** — how hard the code is to understand (accounts for nesting depth, not just branch count). SonarQube computes this automatically.

```bash
# SonarQube (self-hosted or SonarCloud)
sonar-scanner -Dsonar.projectKey=myproject

# Python — radon for cyclomatic + cognitive complexity
pip install radon
radon cc -s -n B .        # show functions with grade B or worse
radon mi -s .             # maintainability index
```

**Duplication:**
- Flag files or modules with >5% duplicate code blocks — duplication hides divergent bugs as copies drift
- Tools: SonarQube, `pylint --disable=all --enable=duplicate-code`, `jscpd`

**Coupling and cohesion:**
- **Afferent coupling (Ca)** — how many modules depend on this one. High Ca = high impact if changed.
- **Efferent coupling (Ce)** — how many modules this one depends on. High Ce = fragile, hard to test in isolation.
- **Instability index** = Ce / (Ca + Ce). Values near 1 = unstable (likely to change); values near 0 = stable (depended upon by many).
- Flag modules that are both unstable (high Ce) and heavily depended upon (high Ca) — these are the highest-risk refactor targets.

**Test coverage:**
- Check what percentage of production code is exercised by tests
- Flag critical paths (auth, payment, data mutations) with <80% branch coverage
- Untested code in security-critical areas is itself a finding

---

### Phase 10 — Architecture Review

Assess structural and design decisions that affect how the system evolves and how failures propagate.

**SOLID principle violations:**

| Principle | What to look for |
|---|---|
| Single Responsibility | Classes/modules doing unrelated things (e.g., a `User` class that also sends email and writes to disk) |
| Open/Closed | Adding features requires modifying existing conditionals rather than extending via interfaces/plugins |
| Liskov Substitution | Subclasses that break parent contracts, require type checks, or throw unexpected exceptions |
| Interface Segregation | Interfaces with many methods, most of which implementations leave empty or raise `NotImplemented` |
| Dependency Inversion | High-level modules importing concrete low-level modules directly instead of through abstractions |

**Layering violations:**
- Business logic in controllers or route handlers — flag as `Code Architecture`
- Database queries in view/template code — flag as `Code Architecture`
- HTTP-specific constructs (request objects, response codes) leaking into domain/service layer
- Verify each layer is independently testable without instantiating the full stack

**Circular dependencies:**
```bash
# Python
pip install pydeps
pydeps src/ --max-bacon=3   # visualize module dependency graph

# Node.js
npx madge --circular src/

# Java
# Use IntelliJ's "Dependency Matrix" or NDepend
```

**Anti-patterns to flag explicitly:**
- **God object** — a single class that knows too much or does too much
- **Feature envy** — a method that uses another class's data more than its own
- **Shotgun surgery** — one logical change requires editing many unrelated files
- **Divergent change** — one class changes for many different reasons
- **Data clumps** — groups of data that always appear together but are not encapsulated

---

### Validation Gate

Before reporting any finding, confirm:
- [ ] The code path is reachable — for security findings, from an untrusted input source; for quality/arch findings, from production code paths
- [ ] The finding is reproducible — write a minimal proof-of-concept, test case, or metric reading that another reviewer can verify independently
- [ ] Impact is demonstrated, not theoretical
- [ ] The fix does not already exist in a newer branch or commit
- [ ] The finding is within the agreed audit scope
- [ ] For business logic findings: the flaw is triggered by a realistic user action, not an impossible state

---

### False Positive Filter

Do not report without further investigation:
- Grep matches in comments, documentation, or test fixtures (not production code)
- Secrets in example or template files clearly marked as placeholders (`YOUR_API_KEY_HERE`)
- Use of `MD5` or `SHA1` for non-security purposes (checksums, cache keys, non-auth IDs)
- `eval()` or `exec()` called only on fully developer-controlled strings (not user input)
- Missing rate limiting on non-sensitive, non-authenticated endpoints
- Dependency CVEs with no reachable code path in the application

---

### Phase 11 — Reporting

#### Report Structure

A complete audit report has five sections:

1. **Executive Summary** — severity distribution, overall risk rating, top 3 most critical findings summarized in business terms (not technical jargon), and a one-paragraph overall assessment
2. **Findings** — full per-finding detail (see template below), ordered by severity descending
3. **Positive Findings** — controls and practices that are working well; this increases report credibility and gives developers actionable confirmation of what to keep doing
4. **Statistics** — finding counts by type and severity, complexity distribution, test coverage summary, dependency risk summary
5. **Remediation Plan** — findings ordered by recommended fix priority, with estimated effort per fix (hours) and dependencies between fixes noted

#### Per-Finding Fields

Each finding must include:
- **Title** — short and action-oriented (e.g. "SQL Injection in user search endpoint")
- **Type** — one of: `Code Quality` / `Code Architecture` / `Code Maintainability` / `Code Security`
- **Severity** — Critical / High / Medium / Low / Info
- **CVSS Score** — for `Code Security` findings: calculate using CVSS v3.1; include the vector string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). For quality/arch/maintainability findings, omit CVSS and use the severity label only.
- **File and line** — exact location (`src/db/users.py:142`)
- **Evidence** — the specific lines of code that demonstrate the issue, plus any tool output, grep result, or metric that confirms it. Evidence must be concrete — no theoretical findings without supporting proof.
- **Steps to trigger** — how the issue is reached or triggered (attacker path for security; reproduction steps for quality/arch/maintainability)
- **Impact** — what breaks, degrades, or becomes exploitable as a result
- **Recommendation** — specific fix with a corrected code example where possible
- **References** — CWE ID, OWASP category, CVE, or relevant design principle (e.g. SOLID, GRASP)

#### Finding Template

```
### [FINDING-ID] Title

**Type:** Code Security | Code Quality | Code Architecture | Code Maintainability
**Severity:** Critical | High | Medium | Low | Info
**CVSS Score:** 9.8 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (Code Security only)
**Location:** `path/to/file.py:42`

**Evidence:**
```language
// paste the exact code lines or tool output that proves this finding
```
> [Optional: scanner output, grep match, complexity metric, or reproduce command]

**Steps to Trigger:**
1. ...

**Impact:**
...

**Recommendation:**
```language
// corrected code example
```

**References:** CWE-XXX, OWASP ASVS X.X.X
```

Use `finding-writer` skill to structure raw notes into a complete finding.
