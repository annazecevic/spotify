# Security Architecture — Spotify Clone

**Security Lead** · Defensive design for a distributed media platform  
*Audience: Technical recruiters (e.g. SOC Analyst roles)*

---

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
