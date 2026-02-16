# Security Architecture


## 1. Introduction: Security Philosophy

This document describes the **defensive architecture** of the Spotify Clone application from a Blue Team perspective. Our approach is **security-first**: we assume a hostile environment and design controls to protect confidentiality, integrity, and availability of user data and system resources.

**Guiding principles:**

- **Defense in depth** — Multiple layers (reverse proxy, application middleware, service logic) enforce security so that a single failure does not compromise the system.
- **Least privilege** — Users and services receive only the minimum access required; sensitive operations are restricted by role.
- **Secure by default** — All client–server communication is over HTTPS; authentication is required for protected resources; input is validated and output is encoded.
- **Observability-ready** — The architecture is prepared for centralized logging and monitoring to support detection and response (see Roadmap).

The controls below map to common threat models (including OWASP Top 10) and are implemented across a **distributed, microservice-based** stack with clear trust boundaries.

---

## 2. Core Security Pillars

| Pillar | Objective | Primary Controls |
|--------|-----------|------------------|
| **Authentication** | Verify identity before granting access | HTTPS, JWT, BCrypt hashing & salting, password policy, token validation at gateway and services |
| **Authorization** | Enforce what authenticated entities may do | Role-Based Access Control (RBAC), mandatory auth checks per request, admin-only endpoints |
| **Availability** | Resist abuse and maintain service uptime | Multi-layer rate limiting, connection limits, request size limits, DoS mitigation at proxy and app |

These pillars are implemented at the **edge (Nginx)**, in **application middleware (Go/Gin)**, and in **service logic**, ensuring consistent enforcement across the system.

---

## 3. Detailed Control Breakdown

### 3.1 Authentication & Data Protection

**Encryption in transit**

- **HTTPS** is enforced for all client–server communication. Plain HTTP is redirected to HTTPS (e.g. `301` to `https://$host:8443$request_uri`).
- TLS is restricted to **TLSv1.2** and **TLSv1.3**; strong cipher suites (e.g. ECDHE, AES-GCM, ChaCha20-Poly1305) are used.
- **HSTS** is enabled (`Strict-Transport-Security: max-age=31536000; includeSubDomains`) to prevent downgrade attacks.
- SSL certificates and Diffie–Hellman parameters are generated for development; production should use CA-signed certificates.

**Protection of credentials and sensitive data**

- **Hashing & salting**: User passwords are never stored in plaintext. We use **BCrypt** with a built-in salt and configurable cost factor. BCrypt is industry-standard for password hashing and provides resistance to rainbow-table and brute-force attacks.

*Logic (conceptual):* Passwords are hashed at registration and password reset; verification uses constant-time comparison (`CompareHashAndPassword`) to reduce timing side channels.

```go
// Registration: hash with salt (BCrypt embeds salt automatically)
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

// Authentication: secure comparison
if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
    return nil, errors.New("invalid credentials")
}
```

- **Password policy**: Enforced server-side (e.g. minimum length, complexity, rejection of common passwords, consecutive character rules) to reduce weak credentials.
- **Password lifecycle**: Optional password expiration and change timestamps support rotation and response to compromise.
- **Password reset**: Time-limited, single-use tokens; reset links sent over email with clear user guidance.

Sensitive configuration (e.g. JWT secret, DB and SMTP credentials) is externalized via environment variables and not committed to version control.

---

### 3.2 Access Control (RBAC)

**Role-Based Access Control** ensures that every protected request is checked for both **identity** and **role**.

- **Roles** (e.g. `user`, `admin`) are stored in the user store and embedded in the **JWT** (e.g. `role` claim). The JWT is validated at the API gateway and/or at each service.
- **Authorization** is mandatory for protected routes: no endpoint serves sensitive data or actions without a valid token and, where required, the appropriate role.

**Enforcement points**

1. **Nginx** — For protected API paths, an `auth_request` subrequest validates the JWT with the user service. Only on success are `X-User-ID` and `X-User-Role` set and the request proxied to backends.
2. **Application middleware** — Each service uses an `AuthMiddleware` that parses the `Authorization: Bearer <token>` header, validates the JWT (signature and claims), and sets `user_id` and `user_role` in the request context.
3. **Role checks** — Sensitive operations (e.g. create/update content, admin-only storage) are protected by `RoleMiddleware` or `AdminOnly()`, which deny access if the role does not match.

*Logic (conceptual):* After JWT validation, the role is read from claims and compared to the required role for the handler; a mismatch results in `403 Forbidden`.

```go
// Role enforcement: every protected admin action requires explicit check
func RoleMiddleware(requiredRole string) gin.HandlerFunc {
    return func(c *gin.Context) {
        role, exists := c.Get("user_role")
        if !exists || role.(string) != requiredRole {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
                "error": "insufficient permissions",
                "required_role": requiredRole,
            })
            return
        }
        c.Next()
    }
}
```

This design preserves **system integrity** by ensuring that only authorized roles can modify content, manage users, or access administrative functions.

---

### 3.3 DoS Mitigation

**Denial of Service** is mitigated at two layers: **reverse proxy** and **application**.

**Proxy layer (Nginx)**

- **Rate limiting** via `limit_req_zone`: different zones for login (e.g. 5 req/min), registration (e.g. 3 req/min), and general API (e.g. 50–100 req/s) to throttle abuse and credential stuffing.
- **Connection limiting** (`limit_conn`) caps concurrent connections per client (e.g. 10) to prevent resource exhaustion.
- **Burst** and `nodelay` are used to allow short spikes while enforcing sustained limits.

**Application layer (Go services)**

- **In-memory rate limiters** (per client IP or per user ID when authenticated) limit requests per time window (e.g. 100/min general, 5/min for login/register/password-reset). Exceeding the limit returns `429 Too Many Requests`.

*Logic (conceptual):* A sliding or fixed window counts requests per identifier; when the count exceeds the limit within the window, the request is rejected and a cleanup routine evicts expired entries.

```go
// Rate limiter: allow(identifier) checks count in window; reject if >= limit
if req.count >= rl.limit {
    return false
}
req.count++
return true
```

Together, these controls reduce the impact of volumetric and application-layer DoS attempts while preserving legitimate traffic.

---

### 3.4 Input Validation (XSS & SQL Injection Mitigation)

We use **strict client-side and server-side validation** plus **output encoding** to neutralize injection and XSS risks.

**Strategy**

- **Whitelisting** — Input is validated against allowed character sets and lengths (e.g. username: alphanumeric, underscore, hyphen; name: letters, spaces, hyphens, apostrophes; email: RFC-style format). Reject invalid input early.
- **Boundary checks** — Length and numeric range limits (e.g. username 3–30 chars, body size 10 MB) prevent buffer and resource abuse.
- **Pattern-based detection** — Server-side checks for common **SQL injection** patterns (e.g. `UNION SELECT`, `'; --`, `OR 1=1`) and **XSS** patterns (e.g. `<script>`, `javascript:`, `onerror=`, `eval(`). Detected patterns result in rejection or sanitization.
- **Sanitization / output encoding** — Before rendering or storing, strings are HTML-escaped (`html.EscapeString`) so that even if malicious input is missed, it is not executed as script or markup.
- **Content-Type and size** — POST/PUT requests must use allowed content types (e.g. `application/json`, `multipart/form-data`); body size is capped.

**Security headers** (Nginx and/or application) reinforce browser behavior:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN` or `DENY`
- `X-XSS-Protection: 1; mode=block`

*Logic (conceptual):* Validation runs in middleware and in handlers; sanitization is applied before persistence or response. Content service applies XSS/SQL pattern checks on sanitized input before accepting content updates.

```go
// Sanitization: escape before storage/display
sanitized := html.EscapeString(input)
sanitized = strings.TrimSpace(sanitized)

// Injection pattern check (e.g. in content handler)
if middleware.CheckXSSPatterns(sanitized) || middleware.CheckSQLInjectionPatterns(sanitized) {
    // Reject or sanitize
}
```

Note: We use MongoDB and parameterized access; the SQL injection checks add defense in depth and protect against NoSQL-style injection where applicable.

---

### 3.5 Infrastructure & Environment Isolation

**Secure, distributed design**

- **Microservices** — User, content, storage, and notifications run as separate services. A compromise in one component is contained by network and authentication boundaries.
- **Reverse proxy** — Nginx is the single public entry point. It terminates TLS, enforces rate limits, and performs auth_request before forwarding; backends are not directly exposed.
- **Isolated runtime** — Services run in **containers** (Docker); orchestration (e.g. Docker Compose) defines isolated networks so that only required service-to-service communication is possible.
- **Environment isolation** — Configuration (e.g. `ENVIRONMENT`, database URIs, JWT secret) is injected via environment variables or env files (e.g. `.env`), keeping secrets out of code and allowing different settings per environment (dev/staging/prod).

This structure supports **secure deployment** and future hardening (e.g. secrets management, network policies).

---

## 4. Threat Model (OWASP Top 10 Alignment)

We defend against the following high-level threats; controls are summarized in the table below.

| Threat / Risk | Mitigation |
|---------------|------------|
| **A01:2021 – Broken Access Control** | RBAC, mandatory auth on every protected request, role middleware on admin and sensitive endpoints |
| **A02:2021 – Cryptographic Failures** | HTTPS only, TLS 1.2/1.3, strong ciphers, BCrypt for passwords, no plaintext credential storage |
| **A03:2021 – Injection** | Input validation, whitelisting, SQL/XSS pattern checks, parameterized DB access, output encoding |
| **A04:2021 – Insecure Design** | Defense in depth, least privilege, security headers, rate limiting, request size limits |
| **A05:2021 – Security Misconfiguration** | Security headers, TLS and HSTS, environment-based config, no default credentials in code |
| **A06:2021 – Vulnerable Components** | Dependency management (Go modules); keep dependencies updated (process not detailed here) |
| **A07:2021 – Identification and Authentication Failures** | Strong password policy, BCrypt, JWT validation, rate limiting on login/register/reset |
| **A08:2021 – Software and Data Integrity** | JWT signature verification, TLS for data in transit, integrity via hashing of uploads where implemented |
| **A09:2021 – Logging and Monitoring Failures** | Architecture prepared for centralized logging (see Roadmap); auth and rate-limit events are candidates for logging |
| **A10:2021 – SSRF** | Backend services not directly exposed; proxy and auth reduce SSRF impact; internal calls use service names |

---

## 5. Security Roadmap (Work in Progress)

The following improvements are planned or in progress to strengthen the security posture and support SOC-style operations.

| Initiative | Status | Description |
|------------|--------|-------------|
| **Centralized Logging & Monitoring** | In progress | Aggregating logs from Nginx and all services into a central store (e.g. ELK, Loki, or SIEM). Standardizing log format (e.g. auth events, rate-limit hits, errors) to support **detection, alerting, and incident response** — essential for SOC analysis. |
| **Multi-Factor Authentication (MFA)** | Planned | Introduction of a second factor (e.g. TOTP or email OTP) for high-risk actions or for all logins. Complements existing password and JWT design and reduces impact of credential theft. |
| **Password hashing** | Optional future | Evaluation of **Argon2** (e.g. Argon2id) as an alternative or complement to BCrypt for new passwords, in line with current recommendations for memory-hard hashing. |

Additional roadmap items may include: formal dependency and vulnerability scanning, automated security tests in CI, and tighter network segmentation in production.

---

## 6. Summary

The Spotify Clone applies a **defense-in-depth**, **security-first** approach across authentication (HTTPS, BCrypt, JWT), authorization (RBAC on every protected request), availability (rate limiting and DoS controls), and input validation (whitelisting, sanitization, XSS/SQL pattern checks). The system is built as a **distributed, environment-isolated** set of services behind a hardened reverse proxy, with a clear **threat model** aligned to OWASP Top 10 and a **security roadmap** focused on centralized logging/monitoring and MFA.

---

## 7. Vulnerability Analysis 

This section summarizes the **vulnerability analysis** of the application. It describes:

- which **tools** were used
- which **vulnerabilities** were identified (per service)
- how they could theoretically be **exploited**
- how we **fixed** them or how to **mitigate** them
- how to **reproduce** the scans (commands), so screenshots can be taken for the report

### 7.1 Tools Used

- **gosec** (SecureGo SAST for Go)  
  Static code analysis of each Go service (user, content, notifications, storage).  
  Focus: common security issues (integer overflows, file access, unhandled errors, secrets, etc.).

- **govulncheck** (Go official vulnerability scanner)  
  Checks Go modules (`go.mod`) for dependencies with known CVEs and verifies if the project’s code actually calls the vulnerable symbols.

> Note: Tools were executed via Docker containers so that no local Go toolchain was required.

### 7.2 How to Run the Scans (Commands)

All commands are run from the project root: `C:\Users\seva0\Desktop\spotify`.

#### 7.2.1 `gosec` — per service

**user-service**

```powershell
docker run --rm -v "${PWD}:/src" -w /src/services/user-service securego/gosec `
    -fmt=json -out=/src/gosec-user-service ./...
```

**content-service**

```powershell
docker run --rm -v "${PWD}:/src" -w /src/services/content-service securego/gosec `
    -fmt=json -out=/src/gosec-content-service ./...
```

**notifications-service**

```powershell
docker run --rm -v "${PWD}:/src" -w /src/services/notifications-service securego/gosec `
    -fmt=json -out=/src/gosec-notifications-service ./...
```

**storage-service**

```powershell
docker run --rm -v "${PWD}:/src" -w /src/services/storage-service securego/gosec `
    -fmt=json -out=/src/gosec-storage-service ./...
```

The JSON outputs (`gosec-*.…`) were used to extract the findings described below.  
Screenshots for the report can be taken directly from the PowerShell console while these commands run.

#### 7.2.2 `govulncheck` — per service (after `go mod tidy`)

Because each service is its own Go module, we ran `govulncheck` in the context of each service, using Go 1.24 (matching `go.mod`).

**user-service**

```powershell
docker run --rm -v "${PWD}:/app" -w /app/services/user-service golang:1.24 `
  sh -c "go mod tidy && \
         go install golang.org/x/vuln/cmd/govulncheck@latest && \
         /go/bin/govulncheck ./... > /app/govuln-user-service.txt"
```

**content-service**

```powershell
docker run --rm -v "${PWD}:/app" -w /app/services/content-service golang:1.24 `
  sh -c "go mod tidy && \
         go install golang.org/x/vuln/cmd/govulncheck@latest && \
         /go/bin/govulncheck ./... > /app/govuln-content-service.txt"
```

**notifications-service**

```powershell
docker run --rm -v "${PWD}:/app" -w /app/services/notifications-service golang:1.24 `
  sh -c "go mod tidy && \
         go install golang.org/x/vuln/cmd/govulncheck@latest && \
         /go/bin/govulncheck ./... > /app/govuln-notifications-service.txt"
```

**storage-service**

```powershell
docker run --rm -v "${PWD}:/app" -w /app/services/storage-service golang:1.24 `
  sh -c "go mod tidy && \
         go install golang.org/x/vuln/cmd/govulncheck@latest && \
         /go/bin/govulncheck ./... > /app/govuln-storage-service.txt"
```

The `govuln-*.txt` files contain the module‑level vulnerability reports which we summarize next.

### 7.3 Findings from `gosec`

#### 7.3.1 Common patterns in all services (loggers)

- **G304 – Potential file inclusion via variable (MEDIUM)**  
  - Files: `services/*-service/logger/logger.go`  
  - Code: `os.OpenFile(path, ...)` in `ensureFilePermissions(path string)`  
  - **Explanation**: gosec warns whenever a file is opened with a variable path. In our case, the path comes from configuration (`LOG_FILE_PATH`), not from user input.  
  - **Potential exploitation**: If an attacker could control `LOG_FILE_PATH` (e.g. by changing container environment), they could redirect logs to an unexpected file. This is an *operational* risk rather than an application bug.  
  - **Mitigation**:
    - Keep environment variables under operational control (no user influence).
    - Optionally validate that `LOG_FILE_PATH` stays under `/var/log/<service>/` before opening the file.

- **G104 – Errors unhandled (LOW)**  
  - Files: `logger/logger.go` in all services.  
  - Examples:
    - Ignoring error from `l.writer.Write(...)` (log write).
    - Ignoring error from `os.Chmod(path, 0600)` or `f.Close()`.  
  - **Explanation**: If these operations fail, we do not log a second error. This is about robustness of logging, not about a direct security breach.  
  - **Mitigation** (optional, if desired):
    - Wrap these calls with `if err != nil { fmt.Fprintf(os.Stderr, "log write failed: %v\n", err) }` to record failures to stderr.

- **G117 – “Secret‑looking” struct fields (MEDIUM)**  
  - Files:
    - `user-service/dto/user_dto.go` (`Password` fields)
    - `user-service/domain/user.go` (`Password` field)
    - `user-service/config/config.go`, `notifications-service/config/config.go`, `storage-service/config/config.go` (`JWTSecret` field)  
  - **Explanation**: gosec flags any struct field whose name or JSON tag looks like a secret. This is a reminder, not a direct vulnerability.  
  - **Mitigation / Current state**:
    - These fields are **never logged in clear text**: the logging layer redacts `password`, `token`, `jwt`, etc.
    - Response DTOs do not expose password or JWT secrets back to the client.

#### 7.3.2 user-service specific (G115)

- **G115 – Integer overflow conversion int → rune (HIGH)**  
  - File: `services/user-service/middleware/validation_middleware.go`  
  - Code created messages using `string(rune(length))`, `string(rune(min))`, `string(rune(max))`.  
  - **Explanation**: Converting integers to `rune` and then to string can produce unexpected characters if the number is large. In practice, we use small lengths, but the pattern is considered unsafe.  
  - **Potential exploitation**: This does not directly allow an attacker to break security; at worst it can cause confusing error messages or strange characters if validation ranges were misconfigured.  
  - **Mitigation**:
    - Replace `string(rune(min))` / `string(rune(max))` with safe integer‑to‑string conversions (`strconv.Itoa(min)` etc.).

#### 7.3.3 content-service specific (G115, G114)

- **G115 – Integer overflow conversion int → rune (HIGH)**  
  - File: `services/content-service/handler/content_handler.go`  
  - Code: building messages like `"must be between " + string(rune(min+'0')) + " and " + string(rune(max+'0')) + " characters"`.  
  - **Explanation / mitigation**: Same pattern as in user-service; fix is to use `strconv.Itoa(min)` / `strconv.Itoa(max)` instead of rune conversions.

- **G114 – net/http server without timeouts (MEDIUM)**  
  - File: `services/content-service/main.go`  
  - Code: `http.ListenAndServe(addr, r)` with no custom `http.Server` timeouts.  
  - **Potential exploitation**: In theory, a malicious client could open slow connections and keep them alive, consuming resources (slowloris-style attack).  
  - **Mitigation** (recommended improvement):
    - Replace `http.ListenAndServe` with an `http.Server` that sets `ReadTimeout`, `WriteTimeout`, `IdleTimeout` to reasonable values (e.g. 10–30 seconds).
    - Note that we already have rate limiting at Nginx and app level, which reduces practical impact.

#### 7.3.4 storage-service specific (G115, extra G104)

- **G115 – Integer overflow conversion uint64 → int64 (HIGH)**  
  - File: `services/storage-service/hdfs/client.go`  
  - Code: `availableSpace = int64(fsInfo.Remaining)`.  
  - **Explanation**: If `fsInfo.Remaining` is extremely large (close to `math.MaxUint64`), conversion to `int64` can overflow. In practice, HDFS reports realistic sizes, but the pattern is unsafe.  
  - **Potential exploitation**: An attacker with control over HDFS metadata could try to spoof remaining space to trick the application into thinking there is more/less space than there really is. This is unlikely in our controlled environment.  
  - **Mitigation**:
    - Check bounds before conversion (e.g. if `fsInfo.Remaining > math.MaxInt64` then clamp to `math.MaxInt64` or treat as error).

- **Extra G104s in storage-service**  
  - Some calls to `io.Copy` and `c.client.Remove(path)` ignore returned errors.  
  - **Mitigation**: As with loggers, add basic error handling to log or handle failures where needed.

#### 7.3.5 notifications-service specific

- Only the generic logger findings (G304, G104) and one G117 on `JWTSecret` in config.  
- **No high-risk, direct exploitability findings** in the notifications service logic itself.

### 7.4 Findings from `govulncheck` (Dependencies)

Here we summarize only vulnerabilities that `govulncheck` reports as **actually reached by our code** (symbol-level findings).

#### 7.4.1 user-service — GO-2025-3595 (`golang.org/x/net`)

- **ID**: `GO-2025-3595`  
- **Module**: `golang.org/x/net`  
- **Found in**: `golang.org/x/net@v0.30.0`  
- **Fixed in**: `golang.org/x/net@v0.38.0`  
- **Trace example**: From `handler/user_handler.go` via `gin.Context.ShouldBindJSON` to `html.Tokenizer.Next`.  
- **Risk (simplified)**:
  - The vulnerability is about incorrect neutralization of input during HTML parsing in `x/net`.  
  - In some setups this could help an attacker craft content that bypasses HTML sanitization or causes unexpected parsing behavior (XSS-like issues).
- **Mitigation applied**:
  - Updated `services/user-service/go.mod` to use:
    - `golang.org/x/net v0.38.0` (fixed version).
  - After this change, a new `govulncheck` scan no longer reports `GO-2025-3595` for user-service.

#### 7.4.2 content-service — GO-2024-2687 (HTTP/2 CONTINUATION flood)

- **ID**: `GO-2024-2687`  
- **Module**: `golang.org/x/net`  
- **Found in**: `golang.org/x/net@v0.10.0`  
- **Fixed in**: `golang.org/x/net@v0.23.0`  
- **Trace example**: Through net/http HTTP/2 internals used indirectly by MongoDB driver and other components.  
- **Risk (simplified)**:
  - Vulnerability in HTTP/2 handling that can allow a remote attacker to send specially crafted frames and cause **resource exhaustion (DoS)** on the server.
- **Mitigation applied**:
  - Updated `services/content-service/go.mod` to use:
    - `golang.org/x/net v0.23.0` (minimum fixed version from advisory; newer versions are also acceptable).
  - Combined with existing rate limiting at Nginx and app level, this significantly reduces DoS risk from HTTP/2 continuation flood.

#### 7.4.3 notifications-service — no reachable vulnerabilities

- `govulncheck` result:
  - `Your code is affected by 0 vulnerabilities.`  
  - It did find some vulnerabilities in transitive modules, but none are reachable from our code paths according to the call graph.
- **Mitigation**:
  - Keep dependencies updated over time.
  - Optionally review transitive findings if stricter compliance is required.

#### 7.4.4 storage-service — GO-2025-3553 (`github.com/golang-jwt/jwt/v5`)

- **ID**: `GO-2025-3553`  
- **Module**: `github.com/golang-jwt/jwt/v5`  
- **Found in**: `github.com/golang-jwt/jwt/v5@v5.2.1`  
- **Fixed in**: `github.com/golang-jwt/jwt/v5@v5.2.2` (and later)  
- **Trace example**: `middleware/middleware.go` calls `jwt.ParseWithClaims`, which reaches `jwt.Parser.ParseUnverified`.  
- **Risk**:
  - An attacker could send many malicious JWTs to try to exhaust memory and cause a DoS on the storage-service.
- **Mitigation applied**:
  - Updated `services/storage-service/go.mod` to use:
    - `github.com/golang-jwt/jwt/v5 v5.3.0` (version without this vulnerability, same as user-service).

### 7.5 Overall Security Level and Protection Against Exploitation

Summarizing all the above:

- **Static code issues (gosec)** are mostly **low to medium risk**: unsafe integer‑to‑rune conversions in error messages, unhandled errors in logging and HDFS client, and generic warnings about file paths and secret‑like struct fields. These do not directly allow an attacker to take over the system, but they highlight areas where code quality and robustness can be improved.
- **Dependency vulnerabilities (govulncheck)** surfaced **three relevant issues**:
  - `GO-2025-3595` (`golang.org/x/net`) in user-service.
  - `GO-2024-2687` (HTTP/2 continuation flood) in content-service.
  - `GO-2025-3553` (`github.com/golang-jwt/jwt/v5`) in storage-service.
  All three have been mitigated by **upgrading to fixed dependency versions** in the corresponding `go.mod` files.
- The existing **defense-in-depth mechanisms** (TLS, RBAC, rate limiting, input validation, sanitized logging, and secure configuration) already provide strong protection against common web attacks (XSS, injection, brute-force, DoS). The dependency upgrades further close known CVE gaps.

