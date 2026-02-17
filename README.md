# Security Architecture and Vulnerability Analysis

## 1. Introduction: Security Philosophy

This document describes the defensive architecture of the Spotify Clone application and the results of a static vulnerability analysis. The goal is to explain:

- how the system is protected (architecture and controls)
- which tools were used to identify weaknesses
- which issues were detected and how they could be exploited
- how to remediate and prevent such issues in the future.

Our approach is **security-first**: we assume a hostile environment and design controls to protect confidentiality, integrity, and availability of user data and system resources.

**Guiding principles:**

- **Defense in depth** — multiple layers (reverse proxy, application middleware, service logic) enforce security so that a single failure does not compromise the system.
- **Least privilege** — users and services receive only the minimum access required; sensitive operations are restricted by role.
- **Secure by default** — all client–server communication is over HTTPS; authentication is required for protected resources; input is validated and output is encoded.
- **Observability-ready** — the architecture is prepared for centralized logging and monitoring to support detection and response.

---

## 2. Core Security Pillars

| Pillar | Objective | Primary Controls |
|--------|-----------|------------------|
| **Authentication** | Verify identity before granting access | HTTPS, JWT, BCrypt hashing and salting, password policy, token validation at gateway and services |
| **Authorization** | Enforce what authenticated entities may do | Role-Based Access Control (RBAC), mandatory auth checks per request, admin-only endpoints |
| **Availability** | Resist abuse and maintain service uptime | Multi-layer rate limiting, connection limits, request size limits, DoS mitigation at proxy and app |

These pillars are implemented at the edge (Nginx), in application middleware (Go/Gin), and in service logic, ensuring consistent enforcement across the system.

---

## 3. Detailed Control Breakdown

### 3.1 Authentication and Data Protection

**Encryption in transit**

- HTTPS is enforced for all client–server communication. Plain HTTP is redirected to HTTPS.
- TLS is restricted to TLSv1.2 and TLSv1.3; strong cipher suites (ECDHE, AES-GCM, ChaCha20-Poly1305) are used.
- HSTS is enabled to prevent downgrade attacks.
- Certificates are generated for development; production should use CA-signed certificates.

**Protection of credentials and sensitive data**

- Hashing and salting: user passwords are never stored in plaintext. We use BCrypt with a built-in salt and configurable cost factor.
- Password policy: minimum length, complexity, and rejection of common passwords reduce weak credentials.
- Password lifecycle: optional expiration and change timestamps support rotation and response to compromise.
- Password reset: time-limited, single-use tokens; reset links sent over email.
- Sensitive configuration (JWT secret, DB and SMTP credentials) is externalized via environment variables and not committed to version control.

Example password handling (conceptual):

```go
// Registration: hash with salt (BCrypt embeds salt automatically)
hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

// Authentication: secure comparison
if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
    return nil, errors.New("invalid credentials")
}
```

---

### 3.2 Access Control (RBAC)

Role-Based Access Control ensures that every protected request is checked for both identity and role.

- Roles (for example `user`, `admin`) are stored in the user store and embedded in the JWT as a `role` claim. The JWT is validated at the API gateway and/or at each service.
- Authorization is mandatory for protected routes: no endpoint serves sensitive data or actions without a valid token and, where required, the appropriate role.

**Enforcement points**

1. **Nginx** — for protected API paths, an `auth_request` subrequest validates the JWT with the user service. Only on success are `X-User-ID` and `X-User-Role` set and the request proxied to backends.
2. **Application middleware** — each service uses an `AuthMiddleware` that parses the `Authorization: Bearer <token>` header, validates the JWT (signature and claims), and sets `user_id` and `user_role` in the request context.
3. **Role checks** — sensitive operations (for example create/update content, admin-only storage) are protected by role middleware, which denies access if the role does not match.

Conceptual role enforcement:

```go
func RoleMiddleware(requiredRole string) gin.HandlerFunc {
    return func(c *gin.Context) {
        role, exists := c.Get("user_role")
        if !exists || role.(string) != requiredRole {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
                "error":         "insufficient permissions",
                "required_role": requiredRole,
            })
            return
        }
        c.Next()
    }
}
```

---

### 3.3 DoS Mitigation

Denial of Service is mitigated at two layers: reverse proxy and application.

**Proxy layer (Nginx)**

- Rate limiting via `limit_req_zone`: different zones for login, registration, and general API to throttle abuse and credential stuffing.
- Connection limiting (`limit_conn`) caps concurrent connections per client to prevent resource exhaustion.

**Application layer (Go services)**

- In-memory rate limiters (per client IP or per user ID when authenticated) limit requests per time window; exceeding the limit returns `429 Too Many Requests`.

---

### 3.4 Input Validation (XSS and Injection Mitigation)

We use strict server-side validation plus output encoding to neutralize injection and XSS risks.

- Whitelisting: input is validated against allowed character sets and lengths (for example username, email).
- Boundary checks: length and numeric range limits prevent buffer and resource abuse.
- Pattern-based detection: server-side checks for common SQL injection and XSS patterns; detected patterns are rejected.
- Sanitization / output encoding: before rendering or storing, strings are HTML-escaped so that even if malicious input is missed, it is not executed as script or markup.
- Content-Type and size: POST/PUT requests must use allowed content types; body size is capped.

Key security headers:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN` (or `DENY`)
- `X-XSS-Protection: 1; mode=block`

Example of sanitization and pattern checking:

```go
sanitized := html.EscapeString(input)
sanitized = strings.TrimSpace(sanitized)

if middleware.CheckXSSPatterns(sanitized) || middleware.CheckSQLInjectionPatterns(sanitized) {
    // reject or sanitize
}
```

---

### 3.5 Infrastructure and Environment Isolation

- **Microservices** — user, content, storage, notifications and subscriptions run as separate services; a compromise in one component is contained by network and authentication boundaries.
- **Reverse proxy** — Nginx is the single public entry point. It terminates TLS, enforces rate limits, and performs auth checks before forwarding; backends are not directly exposed.
- **Isolated runtime** — services run in containers (Docker); Compose defines isolated networks so that only required service-to-service communication is possible.

---

## 4. Threat Model (OWASP Top 10 Alignment)

We defend against the following high-level threats; controls are summarized in the table below.

| Threat / Risk | Mitigation |
|---------------|------------|
| A01:2021 – Broken Access Control | RBAC, mandatory auth on every protected request, role middleware on admin and sensitive endpoints |
| A02:2021 – Cryptographic Failures | HTTPS only, TLS 1.2/1.3, strong ciphers, BCrypt for passwords, no plaintext credential storage |
| A03:2021 – Injection | Input validation, whitelisting, SQL/XSS pattern checks, parameterized DB access, output encoding |
| A04:2021 – Insecure Design | Defense in depth, least privilege, security headers, rate limiting, request size limits |
| A05:2021 – Security Misconfiguration | Security headers, TLS and HSTS, environment-based config, no default credentials in code |
| A06:2021 – Vulnerable Components | Dependency management (Go modules); keep dependencies updated |
| A07:2021 – Identification and Authentication Failures | Strong password policy, BCrypt, JWT validation, rate limiting on login/register/reset |
| A08:2021 – Software and Data Integrity | JWT signature verification, TLS for data in transit, integrity checks for file uploads where implemented |
| A09:2021 – Logging and Monitoring Failures | Architecture prepared for centralized logging; auth and rate-limit events are candidates for logging |
| A10:2021 – SSRF | Backend services not directly exposed; proxy and auth reduce SSRF impact; internal calls use service names |

---

## 5. Security Roadmap (Short Overview)

Planned or recommended improvements that further strengthen the security posture:

- **Centralized logging and monitoring**: aggregate logs from Nginx and all services into a central store (for example ELK, Loki, SIEM) to support detection, alerting and incident response.
- **Multi-Factor Authentication (MFA)**: introduce a second factor (for example TOTP or email OTP) for high-risk actions or for all logins to reduce the impact of credential theft.
- **Password hashing evolution**: evaluate Argon2 (for example Argon2id) as an alternative or complement to BCrypt for new passwords, in line with current best practices.

These items are complementary to the controls already described and can be implemented as future work.

---

## 6. Overall Security Summary

The Spotify Clone applies a defense-in-depth, security-first approach across authentication (HTTPS, BCrypt, JWT), authorization (RBAC on every protected request), availability (rate limiting and DoS controls), and input validation (whitelisting, sanitization, XSS/SQL pattern checks). The system is built as a distributed, environment-isolated set of services behind a hardened reverse proxy, with a threat model aligned to OWASP Top 10 and a clear direction for further improvements.

---

## 7. Analiza ranjivosti

Zahtev 2.21 traži izveštaj o nivou bezbednosti aplikacije:

1. koji alati su korišćeni za identifikaciju ranjivosti  
2. koje ranjivosti su identifikovane i kako se one mogu potencijalno eksploatisati  
3. kako prevazići identifikovane ranjivosti  
4. kako se zaštititi od eksploatacije istih  

### 7.1 Alat korišćen za identifikaciju ranjivosti

- **SonarQube (Community Edition)** — statička analiza koda i kvaliteta, pokrenuta lokalno preko Docker-a.  
  Analizira: ranjivosti (Security), bugove (Reliability), code smells (Maintainability), pokrivenost testovima (Coverage), duplikate (Duplications).  
  Svaki Go mikroservis skeniran je kao zaseban projekat.

Reprodukcija skenova (lokalno):

- Pokretanje SonarQube-a: `docker-compose up -d sonarqube-db sonarqube` i otvaranje `http://localhost:9001`.
- Kreiranje tokena: My Account → Security → Generate Token.
- Analiza jednog servisa:  
  `.\scripts\sonarqube-scan.ps1 -ServiceName <ime-servisa> -Token "<TOKEN>"`
- Analiza svih servisa:  
  `.\scripts\sonarqube-scan-all.ps1 -Token "<TOKEN>"`

---

### 7.2 Rezultati po servisu (rezime)

SonarQube je analizovao 5 Go mikroservisa: `content-service`, `user-service`, `notifications-service`, `storage-service`, `subscriptions-service`.

| Servis | Quality Gate | Security | Reliability | Maintainability issues (High) | Coverage | Duplications | Security Hotspots |
|--------|--------------|----------|------------|-------------------------------|----------|--------------|------------------|
| content-service | Failed (novi kod) | 0 (A) | 0 (A) | 4 | 0.0% | 4.25% (novi kod) | 0 |
| user-service | Passed (sa upozorenjem) | 0 (A) | 0 (A) | 6 | 0.0% | 2.9% (handler: 17.1%) | 0 |
| notifications-service | Passed (sa upozorenjem) | 0 (A) | 0 (A) | 1 | 0.0% | 0.0% | 0 |
| storage-service | Passed (sa upozorenjem) | 0 (A) | 0 (A) | 7 | 0.0% | 0.0% | 0 |
| subscriptions-service | Passed (sa upozorenjem) | 0 (A) | 0 (A) | 2 | 0.0% | 0.0% | 0 |

Ključni zaključci iz tabele:

- Nema detektovanih **Security vulnerabilities** ni **Reliability bugova** (svi servisi imaju ocenu A).
- Identifikovano je ukupno **20 Maintainability issues (High)** — uglavnom duplirani literali i visoka složenost funkcija.
- Code coverage je **0.0%** za sve servise, što znači da nema automatizovanih testova koji bi pokrivali kritične putanje.
- Duplications su generalno niske, ali content-service i user-service imaju povišen procenat za novi kod, posebno u handler slojevima.

---

### 7.3 Identifikovane ranjivosti i potencijalna eksploatacija

SonarQube nije prijavio direktne ranjivosti tipa *Vulnerability*, ali je identifikovao probleme održivosti koji mogu indirektno dovesti do sigurnosnih propusta ako se zanemare.

**1. Duplirani literali (17 issues)**

- Pogađaju validacione i bezbednosne poruke (na primer `"invalid or potentially malicious input detected"`, `"user not authenticated"`, `"user not found"`), HTTP headere (`"Content-Type"`, `"Content-Length"`, `"Accept-Ranges"`, `"X-User-ID"`) i error poruke (`"track not found: %s"`, `"failed to stat file: %w"`, `"failed to decode subscriptions: %w"`).
- Potencijalna eksploatacija:
  - nedosledna primena validacije i autentifikacije ako se poruka ili logika promeni na jednom mestu a ne na drugim;
  - informaciono curenje kroz različite error poruke (otkrivanje da li resurs postoji, da li je problem u bazi, u dekodiranju, i slično);
  - greške u konfiguraciji HTTP odgovora (na primer pogrešan `Content-Type`) koje mogu olakšati XSS ili druge napade.

**2. Visoka Cognitive Complexity u user-service (4 issues)**

- Složene funkcije u handler-ima, middleware-u i servisnom sloju otežavaju razumevanje i code review.
- Potencijalna eksploatacija:
  - logičke greške u autentifikaciji i autorizaciji koje prolaze neprimećene;
  - edge-case scenariji (na primer specifične kombinacije header-a ili stanja korisnika) koji nisu pokriveni testovima i mogu zaobići sigurnosne provere.

**3. Nizak coverage i duplikati koda**

- Bez testova, regresije i bezbednosni problemi mogu ostati neprimećeni tokom refaktorisanja.
- Duplirani kod povećava verovatnoću da se ista greška ili ranjivost pojavi na više mesta i otežava njeno ispravljanje.

---

### 7.4 Kako prevazići identifikovane ranjivosti

Preporučene tehničke mere za otklanjanje uočenih problema:

**1. Konstante umesto dupliranih literala**

- Uvesti jasne konstante za sve ponavljane stringove (error poruke, security poruke, header nazive, MIME tipove).
- Primer (generički):

```go
const (
    ErrInvalidMaliciousInput = "invalid or potentially malicious input detected"
    ErrUserNotAuthenticated  = "user not authenticated"
    HeaderContentType        = "Content-Type"
)
```

- Zameniti sve duplirane literale odgovarajućim konstantama u svim servisima i ponoviti SonarQube sken.

**2. Smanjenje kognitivne složenosti**

- Podeliti preduge funkcije na manje logičke celine (na primer validacija, obrada podataka, generisanje odgovora).
- U auth middleware-u izvući parsiranje tokena, validaciju i proveru uloga u odvojene funkcije.
- Refaktorisati složene funkcije u `user-service` tako da Complexity bude u granicama preporuke SonarQube pravila.

**3. Uvođenje automatizovanih testova i povećanje coverage-a**

- Dodati unit testove za:
  - autentifikaciju i autorizaciju (user-service, subscriptions-service);
  - validaciju i filtriranje inputa (content-service, notifications-service);
  - upload/download i rad sa fajlovima (storage-service).
- Dodati integration testove za ključne API endpoint-e i interakcije sa bazama podataka.
- Postaviti cilj coverage-a (na primer 80%) i uključiti ga u SonarQube Quality Gate.

**4. Smanjenje duplikata koda**

- U `content-service` i `user-service` izvući ponovljene delove handler-a u pomoćne funkcije ili zajedničke module.
- Redovno pratiti Duplications metriku po direktorijumima i refaktorisati kada vrednosti pređu dogovoreni prag.

---

### 7.5 Kako se zaštititi od eksploatacije (proces i prakse)

Pored samog otklanjanja uočenih problema, važno je postaviti proces koji sprečava da se slične slabosti ponovo pojave.

**1. Redovna statička analiza**

- Uvesti pravilo da se SonarQube sken pokreće za svaki veći commit ili pre spajanja grana.
- Pratiti Quality Gate; ako padne zbog novih Security, Reliability ili High Maintainability issues, promene se ne smeju merge-ovati dok problemi ne budu rešeni.

**2. Code review usmeren na bezbednost**

- U code review checkliste uključiti:
  - zabranu novih dupliranih literala za security poruke i headere;
  - proveru da se složene funkcije razlažu na manje celine;
  - proveru da novi kod ima odgovarajuće testove.

**3. Logging i monitoring**

- Centralizovati logove iz svih servisa i proxy sloja.
- Logovati:
  - neuspele pokušaje autentifikacije i autorizacije,
  - odbijene zahteve zbog malicioznog inputa,
  - prekoračenja rate limita.
- Postaviti upozorenja (alerting) za neuobičajene obrasce, na primer veliki broj neuspelih logovanja ili pokušaja sa malicioznim inputom.

**4. Kontinuirano poboljšanje**

- Periodično (na primer kvartalno) analizirati SonarQube izveštaje i fokusirati se na smanjenje broja High severity issues.
- Ažurirati politike i standarde koda na osnovu nalaza (na primer uvesti pravilo da su sve poruke i headeri definisani kroz konstante).

Na ovaj način je zahtev 2.21 ispunjen: alat za analizu je jasno naveden, identifikovane su konkretne slabosti i njihov potencijalni uticaj, a definisane su i tehničke i procesne mere za njihovo otklanjanje i sprečavanje eksploatacije.

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

## 5. Summary

The Spotify Clone applies a **defense-in-depth**, **security-first** approach across authentication (HTTPS, BCrypt, JWT), authorization (RBAC on every protected request), availability (rate limiting and DoS controls), and input validation (whitelisting, sanitization, XSS/SQL pattern checks). The system is built as a **distributed, environment-isolated** set of services behind a hardened reverse proxy, with a clear **threat model** aligned to OWASP Top 10 and a **security roadmap** focused on centralized logging/monitoring and MFA.

---

## 6. Analiza ranjivosti (zahtev 2.21)

Izveštaj o nivou bezbednosti aplikacije obuhvata:

1. **Koji alati su korišćeni** za identifikaciju ranjivosti  
2. **Koje ranjivosti su identifikovane** i kako se one mogu potencijalno eksploatisati  
3. **Kako prevazići** identifikovane ranjivosti  
4. **Kako se zaštititi** od eksploatacije istih  

---

### 6.1 Alati korišćeni za identifikaciju ranjivosti

- **SonarQube (Community Edition)** — statička analiza koda i kvaliteta, pokreće se lokalno preko Docker-a.  
  Analizira: ranjivosti (Security), bugove (Reliability), code smells (Maintainability), pokrivenost testovima (Coverage), duplikate (Duplications).  
  Svaki Go mikroservis skenira se kao zaseban projekat u SonarQube-u.

**Kako ponoviti skenove (reprodukcija):**  
Pokretanje SonarQube-a: `docker-compose up -d sonarqube-db sonarqube`. Otvoriti http://localhost:9001, kreirati token (My Account → Security → Generate Token).  
Jedan servis: `.\scripts\sonarqube-scan.ps1 -ServiceName <ime-servisa> -Token "TOKEN"`.  
Svi servisi: `.\scripts\sonarqube-scan-all.ps1 -Token "TOKEN"`.  
Projekti: http://localhost:9001/projects ; pojedinačni: http://localhost:9001/dashboard?id=spotify-*service-name*.

---

### 6.2 Rezultati po servisu — šta da slikaš (korak po korak)

Za svaki servis redom uradimo isti set slika; zatim na osnovu slika sastavljamo tekst: identifikovane ranjivosti, kako se mogu eksploatisati, kako prevazići, kako se zaštititi.

---

#### Servis 1: **content-service**

**Dashboard:** http://localhost:9001/dashboard?id=spotify-content-service

**Slika 1 — Overview (pregled projekta)**

![Content Service Overview](assets/content-service-overview.png)

**Rezime:** Quality Gate **Failed** za "New Code". Pronađeno: **4 issues**, **0.0% Coverage** (ispod zahteva 80%), **4.25% Duplications** (iznad zahteva 3%). Security: 0 issues (A), Reliability: 0 issues (A), Maintainability: 4 issues (A). Lines of Code: 1.7k.

---

**Slika 2 — Issues (identifikovane ranjivosti / problemi)**

![Content Service Issues](assets/content-service-issues.png)

**Identifikovane ranjivosti / problemi:**

1. **`handler/content_handler.go:142`** — Duplikovani literal `'artist id is required'` (3 puta). Maintainability, High.
2. **`handler/content_handler.go:276`** — Duplikovani literal `'invalid or potentially malicious input detected'` (5 puta). Maintainability, High.
3. **`repository/content_repository.go:148`** — Duplikovani literal `'$options'` (3 puta). Maintainability, High.
4. **`repository/content_repository.go:148`** — Duplikovani literal `'$regex'` (3 puta). Maintainability, High.

**Kako se mogu potencijalno eksploatisati:**

- Duplikovani literali povećavaju rizik od grešaka pri izmenama: ako se poruka promeni na jednom mestu, ostala mesta mogu ostati zastarela, što može dovesti do konfuznih poruka ili nedoslednog ponašanja.
- Posebno važno za `'invalid or potentially malicious input detected'`: ako se poruka promeni ili ukloni na jednom mestu, validacija može postati nedosledna, što može omogućiti propuštanje malicioznog inputa.
- Veća verovatnoća tipografskih grešaka u dupliranim stringovima, što može dovesti do neočekivanog ponašanja ili propuštanja validacije.

**Kako prevazići:**

- Definisati konstante za sve duplikovane literale:
  ```go
  // U handler/content_handler.go
  const (
      ErrArtistIDRequired = "artist id is required"
      ErrInvalidInput = "invalid or potentially malicious input detected"
  )
  
  // U repository/content_repository.go
  const (
      MongoOptionKey = "$options"
      MongoRegexKey = "$regex"
  )
  ```
- Zameniti sve pojave dupliranih literala sa konstantama.
- Nakon izmene, ponoviti SonarQube sken da se potvrdi da su issues rešeni.

**Kako se zaštititi od eksploatacije:**

- Redovno pokretanje SonarQube skenova (npr. pre svakog merge-a) da se otkriju novi duplikati.
- Praćenje Quality Gate-a: ako padne zbog duplikata, blokirati merge dok se ne isprave.
- Code review: proveriti da li se koriste konstante umesto dupliranih literala, posebno za poruke validacije i bezbednosti.
- Automatizacija: integrisati SonarQube u CI/CD pipeline da automatski proverava Quality Gate.

---

**Slika 3 — Security Hotspots**

![Content Service Security Hotspots](assets/content-service-security-hotspots.png)

**Rezime:** **0 Security Hotspots** — nema lokacija koje zahtevaju ručni pregled sa sigurnosnog aspekta.

---

**Slika 4 — Duplications (duplikati)**

![Content Service Duplications](assets/content-service-duplications.png)

**Rezime:** U `handler` direktorijumu (`content_handler.go`): **13.3% duplikata** (559 linija koda). Duplikati su povezani sa issues iz Slike 2 (duplikovani literali).

**Kako prevazići:** Refaktorisati kod da se uklone duplikati — izvući zajedničke delove u funkcije ili konstante (vidi preporuke iz Slike 2).

**Kako se zaštititi:** Redovno praćenje metrike Duplications u SonarQube-u; Quality Gate zahteva ≤ 3% duplikata, trenutno je 4.25% za "New Code", što je razlog za Failed status.

---

**Ukupan rezime za content-service:**

- **Security:** 0 issues (A) — nema direktnih ranjivosti.
- **Reliability:** 0 issues (A) — nema bugova.
- **Maintainability:** 4 issues (High) — duplikovani literali u handler i repository slojevima.
- **Coverage:** 0.0% — nema testova; Quality Gate zahteva ≥ 80%.
- **Duplications:** 4.25% (New Code) — iznad zahteva 3%.

**Glavni razlog za Quality Gate Failed:** Nizak coverage (0% vs zahtev 80%) i visok procenat duplikata (4.25% vs zahtev 3%).

---

#### Servis 2: **user-service**

**Dashboard:** http://localhost:9001/dashboard?id=spotify-user-service

**Slika 1 — Overview (pregled projekta)**

![User Service Overview](assets/user-service-overview.png)

**Rezime:** Quality Gate **Passed** (sa upozorenjem "The last analysis has warnings"). Pronađeno: **6 issues** (sve Maintainability). Security: 0 issues (A), Reliability: 0 issues (A), Maintainability: 6 issues (A). Coverage: 0.0% (777 linija bez pokrivenosti), Duplications: 2.9% (3k linija). Lines of Code: 2.4k.

---

**Slika 2 — Issues (identifikovane ranjivosti / problemi)**

![User Service Issues](assets/user-service-issues.png)

**Identifikovane ranjivosti / problemi:**

1. **`handler/user_handler.go:146`** — Duplikovani literal `'X-User-ID'` (4 puta). Maintainability, High.
2. **`handler/user_handler.go:154`** — Cognitive Complexity 30 (dozvoljeno 15). Maintainability, High.
3. **`middleware/auth_middleware.go:15`** — Cognitive Complexity 20 (dozvoljeno 15). Maintainability, High.
4. **`service/user_service.go:298`** — Duplikovani literal `'user not found'` (3 puta). Maintainability, High.
5. **`service/user_service.go:426`** — Cognitive Complexity 17 (dozvoljeno 15). Maintainability, High.
6. **`utils/password_validator.go:8`** — Cognitive Complexity 16 (dozvoljeno 15). Maintainability, High.

**Kako se mogu potencijalno eksploatisati:**

- **Duplikovani literali (`'X-User-ID'`, `'user not found'`):** Isti rizik kao u content-service — nedoslednost pri izmenama može dovesti do grešaka u autentifikaciji/autorizaciji. Posebno kritično za `'X-User-ID'` jer se koristi u middleware za proveru identiteta; ako se header promeni na jednom mestu a ne na drugom, može doći do propuštanja autorizacije.
- **Visoka Cognitive Complexity (30, 20, 17, 16):** Složene funkcije su teže za razumevanje i održavanje, što povećava verovatnoću grešaka. U `user_handler.go:154` (Complexity 30) i `auth_middleware.go:15` (Complexity 20) — kritične tačke za autentifikaciju — visoka složenost može maskirati logičke greške koje napadač može iskoristiti (npr. propuštanje provere, pogrešna logika autorizacije).
- **Nedoslednost u error porukama (`'user not found'`):** Ako se poruka promeni na jednom mestu, može doći do konfuzije pri debugovanju ili do informacijskog curenja (različite poruke mogu otkriti različite informacije o sistemu).

**Kako prevazići:**

- **Duplikovani literali:**
  ```go
  // U handler/user_handler.go
  const HeaderUserID = "X-User-ID"
  
  // U service/user_service.go
  const ErrUserNotFound = "user not found"
  ```
  Zameniti sve pojave sa konstantama.

- **Cognitive Complexity:**
  - **`user_handler.go:154` (Complexity 30):** Podeliti funkciju na manje funkcije (npr. izvući validaciju, obradu podataka, generisanje odgovora u zasebne funkcije).
  - **`auth_middleware.go:15` (Complexity 20):** Pojednostaviti logiku autentifikacije — izvući parsiranje tokena, validaciju, postavljanje konteksta u zasebne funkcije.
  - **`user_service.go:426` (Complexity 17) i `password_validator.go:8` (Complexity 16):** Refaktorisati u manje funkcije sa jasnom odgovornošću.

**Kako se zaštititi od eksploatacije:**

- Redovno pokretanje SonarQube skenova i praćenje Cognitive Complexity metrike — funkcije sa Complexity > 15 su rizične za kritične delove (auth, validacija).
- Code review fokusiran na autentifikaciju/autorizaciju — posebno proveriti `auth_middleware.go` i `user_handler.go` zbog visoke složenosti.
- Dodavanje unit testova za složene funkcije (posebno auth middleware) da se pokriju različiti scenariji i smanji rizik od logičkih grešaka.
- Refaktorisanje pre merge-a — blokirati merge ako Cognitive Complexity prelazi prag (npr. 15) za kritične funkcije.

---

**Slika 3 — Security Hotspots**

![User Service Security Hotspots](assets/user-service-security-hotspots.png)

**Rezime:** **0 Security Hotspots** — nema lokacija koje zahtevaju ručni pregled sa sigurnosnog aspekta.

---

**Slika 4 — Duplications (duplikati)**

![User Service Duplications](assets/user-service-duplications.png)

**Rezime:** Ukupno **2.9% duplikata** (3k linija). **`handler` direktorijum ima 17.1% duplikata** (446 linija) — najveći procenat u servisu. Ostali direktorijumi imaju 0% duplikata.

**Kako prevazići:** Refaktorisati `handler` direktorijum — izvući zajedničke delove u helper funkcije ili middleware. Duplikovani literali (vidi Issues) su deo problema.

**Kako se zaštititi:** Praćenje Duplications metrike po direktorijumu; `handler` direktorijum sa 17.1% je kritičan — refaktorisati pre nego što se poveća.

---

**Ukupan rezime za user-service:**

- **Security:** 0 issues (A) — nema direktnih ranjivosti.
- **Reliability:** 0 issues (A) — nema bugova.
- **Maintainability:** 6 issues (High) — 2 duplikovana literala, 4 funkcije sa visokom Cognitive Complexity.
- **Coverage:** 0.0% — nema testova; Quality Gate zahteva ≥ 80%.
- **Duplications:** 2.9% overall (Passed), ali `handler` direktorijum ima 17.1% (kritično).

**Glavni razlog za Quality Gate Passed (sa upozorenjem):** Nizak coverage (0% vs zahtev 80%) i visoka Cognitive Complexity u kritičnim funkcijama (auth, handler) predstavljaju rizik za održivost i bezbednost.

---

#### Servis 3: **notifications-service**

**Dashboard:** http://localhost:9001/dashboard?id=spotify-notifications-service

**Slika 1 — Overview (pregled projekta)**

![Notifications Service Overview](assets/notifications-service-overview.png)

**Rezime:** Quality Gate **Passed** (sa upozorenjem "The last analysis has warnings"). Pronađeno: **1 issue** (Maintainability). Security: 0 issues (A), Reliability: 0 issues (A), Maintainability: 1 issue (A). Coverage: 0.0% (186 linija bez pokrivenosti), Duplications: 0.0%. Lines of Code: 694.

---

**Slika 2 — Issues (identifikovane ranjivosti / problemi)**

![Notifications Service Issues](assets/notifications-service-issues.png)

**Identifikovane ranjivosti / problemi:**

1. **`handler/notification_handler.go:30`** — Duplikovani literal `"invalid or potentially malicious input detected"` (3 puta). Maintainability, High.

**Kako se mogu potencijalno eksploatisati:**

- **Duplikovani security error literal (`"invalid or potentially malicious input detected"`):** Ova poruka je direktno vezana za detekciju malicioznog inputa. Ako se poruka ili logika vezana za nju promeni na jednom mestu a ne na drugom, može doći do nedoslednosti u validaciji inputa. Napadač može iskoristiti različite instance ove poruke da zaključi gde se validacija izvršava i da probije zaštitu na određenim endpoint-ima. Takođe, nedosledne poruke mogu maskirati različite tipove napada (npr. SQL injection vs XSS vs path traversal), što otežava incident response i može sakriti specifične sigurnosne probleme. Ako se jedna instanca ažurira sa boljom validacijom a druge ne, napadač može probiti zaštitu kroz neažurirane instance.

**Kako prevazići:**

- **Definisati konstantu za security error poruku:**
  ```go
  // U handler/notification_handler.go ili u poseban security/constants.go
  const ErrInvalidMaliciousInput = "invalid or potentially malicious input detected"
  ```
- Zameniti sve pojave dupliranih literala sa konstantom.
- Razmotriti kreiranje centralizovanog security error handling modula koji koristi konstantu i obezbeđuje konzistentno logovanje i response za sve slučajeve malicioznog inputa.
- Nakon izmene, ponoviti SonarQube sken da se potvrdi da su issues rešeni.

**Kako se zaštititi od eksploatacije:**

- Redovno pokretanje SonarQube skenova da se otkriju novi duplikati, posebno u handler slojevima koji su kritični za validaciju inputa i sigurnost.
- Code review fokusiran na input validaciju — proveriti da li se koriste konstante umesto dupliranih literala za security error poruke.
- Centralizovani security error handling — kreirati modul koji upravlja svim security error porukama i logovanjem, umesto da se dupliraju literali.
- Testiranje različitih scenarija malicioznog inputa (SQL injection, XSS, path traversal, itd.) da se potvrdi da su poruke konzistentne na svim endpoint-ima.
- Praćenje Quality Gate-a — iako je Passed, upozorenje ukazuje na issues koje treba rešiti.

---

**Slika 3 — Security Hotspots**

![Notifications Service Security Hotspots](assets/notifications-service-security-hotspots.png)

**Rezime:** **0 Security Hotspots** — nema lokacija koje zahtevaju ručni pregled sa sigurnosnog aspekta.

---

**Slika 4 — Duplications (duplikati)**

![Notifications Service Duplications](assets/notifications-service-duplications.png)

**Rezime:** Ukupno **0.0% duplikata** (846 linija). Svi direktorijumi (`config`, `domain`, `handler`, `logger`, `middleware`, `repository`, `service`) i `main.go` imaju 0% duplikata. Duplikati su u obliku dupliranih literala (vidi Issues), ne blokova koda.

**Kako prevazići:** Definisati konstantu za duplikovani literal (vidi preporuke iz Slike 2).

**Kako se zaštititi:** Iako je Duplications 0%, Issues pokazuju da postoji duplikovani literal koji treba refaktorisati u konstantu. Redovno praćenje Issues metrike, ne samo Duplications, posebno za security-relevantne poruke.

---

**Ukupan rezime za notifications-service:**

- **Security:** 0 issues (A) — nema direktnih ranjivosti.
- **Reliability:** 0 issues (A) — nema bugova.
- **Maintainability:** 1 issue (High) — duplikovani security error literal u handler sloju.
- **Coverage:** 0.0% — nema testova; Quality Gate zahteva ≥ 80%.
- **Duplications:** 0.0% (Passed) — nema dupliranih blokova koda, ali postoji duplikovani security-relevantni literal.

**Glavni razlog za Quality Gate Passed (sa upozorenjem):** Nizak coverage (0% vs zahtev 80%) i 1 Maintainability issue (duplikovani security error literal) koje treba refaktorisati za bolju održivost i konzistentnost u validaciji malicioznog inputa.

---

#### Servis 4: **storage-service**

**Dashboard:** http://localhost:9001/dashboard?id=spotify-storage-service

**Slika 1 — Overview (pregled projekta)**

![Storage Service Overview](assets/storage-service-overview.png)

**Rezime:** Quality Gate **Passed** (sa upozorenjem "The last analysis has warnings"). Pronađeno: **7 issues** (sve Maintainability). Security: 0 issues (A), Reliability: 0 issues (A), Maintainability: 7 issues (A). Coverage: 0.0% (329 linija bez pokrivenosti), Duplications: 0.0%. Lines of Code: 944.

---

**Slika 2 — Issues (identifikovane ranjivosti / problemi)**

![Storage Service Issues](assets/storage-service-issues.png)

**Identifikovane ranjivosti / problemi:**

**U `handler/storage_handler.go`:**
1. **Linija 32** — Duplikovani literal `'track_id is required'` (4 puta). Maintainability, High.
2. **Linija 48** — Duplikovani literal `'Content-Type'` (4 puta). Maintainability, High.
3. **Linija 113** — Duplikovani literal `'Content-Length'` (3 puta). Maintainability, High.
4. **Linija 114** — Duplikovani literal `'Accept-Ranges'` (3 puta). Maintainability, High.

**U `hdfs/client.go`:**
5. **Linija 98** — Duplikovani literal `'track not found: %s'` (4 puta). Maintainability, High.
6. **Linija 100** — Duplikovani literal `'failed to stat file: %w'` (3 puta). Maintainability, High.
7. **Linija 113** — Duplikovani literal `'audio/mpeg'` (4 puta). Maintainability, High.

**Kako se mogu potencijalno eksploatisati:**

- **Duplikovani HTTP header literali (`'Content-Type'`, `'Content-Length'`, `'Accept-Ranges'`):** Ako se header promeni na jednom mestu a ne na drugom, može doći do nedoslednosti u HTTP odgovorima. Napadač može iskoristiti nedoslednost da probije cache ili da izazove neočekivano ponašanje u klijentu (npr. pogrešan Content-Type može dovesti do XSS ako se fajl renderuje kao HTML umesto kao download).
- **Duplikovani error poruke (`'track not found: %s'`, `'failed to stat file: %w'`):** Nedosledne error poruke mogu otkriti informacije o sistemu (npr. različite poruke za različite scenarije mogu otkriti da li fajl postoji, da li je problem sa HDFS-om, itd.). To može pomoći napadaču u reconnaissance fazi.
- **Duplikovani MIME type (`'audio/mpeg'`):** Ako se MIME type promeni na jednom mestu, može doći do nedoslednosti — fajl može biti poslužen sa pogrešnim Content-Type, što može dovesti do problema sa bezbednošću (npr. ako se audio fajl posluži kao `text/html`, browser može pokušati da ga renderuje).
- **Duplikovani validation literal (`'track_id is required'`):** Ako se poruka promeni na jednom mestu, validacija može postati nedosledna, što može omogućiti propuštanje validacije na nekim endpoint-ima.

**Kako prevazići:**

- **Definisati konstante za HTTP headere:**
  ```go
  // U handler/storage_handler.go
  const (
      HeaderContentType = "Content-Type"
      HeaderContentLength = "Content-Length"
      HeaderAcceptRanges = "Accept-Ranges"
  )
  ```

- **Definisati konstante za error poruke:**
  ```go
  // U hdfs/client.go
  const (
      ErrTrackNotFound = "track not found: %s"
      ErrFailedToStatFile = "failed to stat file: %w"
  )
  ```

- **Definisati konstante za MIME type:**
  ```go
  // U hdfs/client.go ili u poseban constants.go
  const MIMETypeAudioMPEG = "audio/mpeg"
  ```

- **Definisati konstante za validation poruke:**
  ```go
  // U handler/storage_handler.go
  const ErrTrackIDRequired = "track_id is required"
  ```

- Zameniti sve pojave dupliranih literala sa konstantama.

**Kako se zaštititi od eksploatacije:**

- Redovno pokretanje SonarQube skenova da se otkriju novi duplikati, posebno u handler i hdfs slojevima koji su kritični za bezbednost fajlova.
- Code review fokusiran na HTTP headere i MIME type-ove — proveriti da li se koriste konstante umesto dupliranih literala.
- Testiranje različitih scenarija (npr. različiti MIME type-ovi, različiti error scenariji) da se potvrdi da su poruke konzistentne.
- Praćenje Quality Gate-a — iako je Passed, upozorenje ukazuje na issues koje treba rešiti.

---

**Slika 3 — Security Hotspots**

![Storage Service Security Hotspots](assets/storage-service-security-hotspots.png)

**Rezime:** **0 Security Hotspots** — nema lokacija koje zahtevaju ručni pregled sa sigurnosnog aspekta.

---

**Slika 4 — Duplications (duplikati)**

![Storage Service Duplications](assets/storage-service-duplications.png)

**Rezime:** Ukupno **0.0% duplikata** (1.1k linija). Svi direktorijumi (`config`, `handler`, `hdfs`, `logger`, `middleware`) i `main.go` imaju 0% duplikata. Duplikati su u obliku dupliranih literala (vidi Issues), ne blokova koda.

**Kako prevazići:** Definisati konstante za duplikovane literale (vidi preporuke iz Slike 2).

**Kako se zaštititi:** Iako je Duplications 0%, Issues pokazuju da postoje duplikovani literali koji treba refaktorisati u konstante. Redovno praćenje Issues metrike, ne samo Duplications.

---

**Ukupan rezime za storage-service:**

- **Security:** 0 issues (A) — nema direktnih ranjivosti.
- **Reliability:** 0 issues (A) — nema bugova.
- **Maintainability:** 7 issues (High) — svi su duplikovani literali u handler i hdfs slojevima.
- **Coverage:** 0.0% — nema testova; Quality Gate zahteva ≥ 80%.
- **Duplications:** 0.0% (Passed) — nema dupliranih blokova koda, ali postoje duplikovani literali.

**Glavni razlog za Quality Gate Passed (sa upozorenjem):** Nizak coverage (0% vs zahtev 80%) i 7 Maintainability issues (duplikovani literali) koje treba refaktorisati za bolju održivost i konzistentnost.

---

#### Servis 5: **subscriptions-service**

**Dashboard:** http://localhost:9001/dashboard?id=spotify-subscriptions-service

**Slika 1 — Overview (pregled projekta)**

![Subscriptions Service Overview](assets/subscriptions-service-overview.png)

**Rezime:** Quality Gate **Passed** (sa upozorenjem "The last analysis has warnings"). Pronađeno: **2 issues** (sve Maintainability). Security: 0 issues (A), Reliability: 0 issues (A), Maintainability: 2 issues (A). Coverage: 0.0% (300 linija bez pokrivenosti), Duplications: 0.0%. Lines of Code: 964.

---

**Slika 2 — Issues (identifikovane ranjivosti / problemi)**

![Subscriptions Service Issues](assets/subscriptions-service-issues.png)

**Identifikovane ranjivosti / problemi:**

1. **`handler/subscription_handler.go:27`** — Duplikovani literal `'user not authenticated'` (4 puta). Maintainability, High.
2. **`repository/subscription_repository.go:94`** — Duplikovani literal `'failed to decode subscriptions: %w'` (3 puta). Maintainability, High.

**Kako se mogu potencijalno eksploatisati:**

- **Duplikovani authentication error literal (`'user not authenticated'`):** Ako se poruka promeni na jednom mestu a ne na drugom, može doći do nedoslednosti u autentifikaciji. Napadač može iskoristiti različite poruke da zaključi gde se provera izvršava i da probije autentifikaciju na određenim endpoint-ima. Takođe, nedosledne poruke mogu maskirati različite tipove grešaka (npr. invalid token vs expired token), što otežava debugovanje i može sakriti sigurnosne probleme.
- **Duplikovani error poruka za dekodiranje (`'failed to decode subscriptions: %w'`):** Nedosledne error poruke mogu otkriti informacije o strukturi podataka ili o tome gde se dešava greška u procesu dekodiranja. To može pomoći napadaču u reconnaissance fazi ili u crafting malicioznih payload-a koji eksploatišu specifične greške u parsiranju.

**Kako prevazići:**

- **Definisati konstante za error poruke:**
  ```go
  // U handler/subscription_handler.go
  const ErrUserNotAuthenticated = "user not authenticated"
  
  // U repository/subscription_repository.go
  const ErrFailedToDecodeSubscriptions = "failed to decode subscriptions: %w"
  ```
- Zameniti sve pojave dupliranih literala sa konstantama.
- Nakon izmene, ponoviti SonarQube sken da se potvrdi da su issues rešeni.

**Kako se zaštititi od eksploatacije:**

- Redovno pokretanje SonarQube skenova da se otkriju novi duplikati, posebno u handler i repository slojevima koji su kritični za autentifikaciju i obradu podataka.
- Code review fokusiran na autentifikaciju — proveriti da li se koriste konstante umesto dupliranih literala za error poruke.
- Testiranje različitih scenarija autentifikacije da se potvrdi da su poruke konzistentne na svim endpoint-ima.
- Praćenje Quality Gate-a — iako je Passed, upozorenje ukazuje na issues koje treba rešiti.

---

**Slika 3 — Security Hotspots**

![Subscriptions Service Security Hotspots](assets/subscriptions-service-security-hotspots.png)

**Rezime:** **0 Security Hotspots** — nema lokacija koje zahtevaju ručni pregled sa sigurnosnog aspekta.

---

**Slika 4 — Duplications (duplikati)**

![Subscriptions Service Duplications](assets/subscriptions-service-duplications.png)

**Rezime:** Ukupno **0.0% duplikata** (1.1k linija). Svi direktorijumi (`config`, `domain`, `dto`, `handler`, `logger`, `middleware`, `repository`, `service`) i `main.go` imaju 0% duplikata. Duplikati su u obliku dupliranih literala (vidi Issues), ne blokova koda.

**Kako prevazići:** Definisati konstante za duplikovane literale (vidi preporuke iz Slike 2).

**Kako se zaštititi:** Iako je Duplications 0%, Issues pokazuju da postoje duplikovani literali koji treba refaktorisati u konstante. Redovno praćenje Issues metrike, ne samo Duplications.

---

**Ukupan rezime za subscriptions-service:**

- **Security:** 0 issues (A) — nema direktnih ranjivosti.
- **Reliability:** 0 issues (A) — nema bugova.
- **Maintainability:** 2 issues (High) — duplikovani literali u handler i repository slojevima.
- **Coverage:** 0.0% — nema testova; Quality Gate zahteva ≥ 80%.
- **Duplications:** 0.0% (Passed) — nema dupliranih blokova koda, ali postoje duplikovani literali.

**Glavni razlog za Quality Gate Passed (sa upozorenjem):** Nizak coverage (0% vs zahtev 80%) i 2 Maintainability issues (duplikovani literali) koje treba refaktorisati za bolju održivost i konzistentnost, posebno u autentifikaciji.

---

### 6.3 Identifikovane ranjivosti i kako se mogu eksploatisati

Na osnovu SonarQube analize svih 5 Go mikroservisa, identifikovano je **ukupno 20 Maintainability issues** (svi High severity). **Nema direktnih Security vulnerabilities ili Reliability bugova** (svi servisi imaju A rating za Security i Reliability). Međutim, Maintainability issues mogu indirektno uticati na bezbednost i mogu se potencijalno eksploatisati.

#### Ukupan pregled nalaza po servisima:

| Servis | Security Issues | Reliability Issues | Maintainability Issues | Coverage | Duplications | Security Hotspots |
|--------|----------------|-------------------|----------------------|----------|--------------|------------------|
| **content-service** | 0 (A) | 0 (A) | 4 (High) | 0.0% | 4.25% | 0 |
| **user-service** | 0 (A) | 0 (A) | 6 (High) | 0.0% | 2.9% (handler: 17.1%) | 0 |
| **notifications-service** | 0 (A) | 0 (A) | 1 (High) | 0.0% | 0.0% | 0 |
| **storage-service** | 0 (A) | 0 (A) | 7 (High) | 0.0% | 0.0% | 0 |
| **subscriptions-service** | 0 (A) | 0 (A) | 2 (High) | 0.0% | 0.0% | 0 |
| **UKUPNO** | **0** | **0** | **20** | **0.0%** | **0.0% - 4.25%** | **0** |

#### Kategorije identifikovanih problema:

**1. Duplikovani literali (17 issues):**

- **Security-relevantni literali:**
  - `"invalid or potentially malicious input detected"` — content-service (5 puta), notifications-service (3 puta)
  - `"user not authenticated"` — subscriptions-service (4 puta)
  - `"user not found"` — user-service (3 puta)
  
- **HTTP headeri i MIME type-ovi:**
  - `"Content-Type"`, `"Content-Length"`, `"Accept-Ranges"` — storage-service (3-4 puta svaki)
  - `"audio/mpeg"` — storage-service (4 puta)
  - `"X-User-ID"` — user-service (4 puta)
  
- **Validation i error poruke:**
  - `"artist id is required"` — content-service (3 puta)
  - `"track_id is required"` — storage-service (4 puta)
  - `"failed to decode subscriptions: %w"` — subscriptions-service (3 puta)
  - `"track not found: %s"`, `"failed to stat file: %w"` — storage-service (3-4 puta)
  
- **MongoDB query literali:**
  - `"$options"`, `"$regex"` — content-service (3 puta svaki)

**2. Visoka Cognitive Complexity (4 issues u user-service):**

- `handler/user_handler.go:154` — Complexity 30 (dozvoljeno 15)
- `middleware/auth_middleware.go:15` — Complexity 20 (dozvoljeno 15)
- `service/user_service.go:426` — Complexity 17 (dozvoljeno 15)
- `utils/password_validator.go:8` — Complexity 16 (dozvoljeno 15)

#### Kako se mogu potencijalno eksploatisati:

**1. Duplikovani security-relevantni literali:**

- **Nedoslednost u validaciji malicioznog inputa:** Ako se poruka `"invalid or potentially malicious input detected"` ili logika vezana za nju promeni na jednom mestu a ne na drugom, napadač može iskoristiti različite instance da zaključi gde se validacija izvršava i da probije zaštitu na određenim endpoint-ima. Ako se jedna instanca ažurira sa boljom validacijom a druge ne, napadač može probiti zaštitu kroz neažurirane instance.
  
- **Nedoslednost u autentifikaciji/autorizaciji:** Duplikovani literali kao `"user not authenticated"` i `"X-User-ID"` u kritičnim handler i middleware slojevima mogu dovesti do propuštanja autorizacije ako se header ili poruka promene na jednom mestu a ne na drugom. Napadač može probiti autentifikaciju na određenim endpoint-ima ako validacija nije konzistentna.

- **Informacijsko curenje kroz error poruke:** Nedosledne error poruke (`"user not found"`, `"track not found"`, `"failed to decode subscriptions"`) mogu otkriti informacije o sistemu (npr. različite poruke za različite scenarije mogu otkriti da li resurs postoji, da li je problem sa bazom podataka, itd.). To može pomoći napadaču u reconnaissance fazi ili u crafting malicioznih payload-a.

**2. Duplikovani HTTP headeri i MIME type-ovi:**

- **Nedoslednost u HTTP odgovorima:** Ako se header (`"Content-Type"`, `"Content-Length"`, `"Accept-Ranges"`) promeni na jednom mestu a ne na drugom, može doći do nedoslednosti u HTTP odgovorima. Napadač može iskoristiti nedoslednost da probije cache ili da izazove neočekivano ponašanje u klijentu (npr. pogrešan Content-Type može dovesti do XSS ako se fajl renderuje kao HTML umesto kao download).

- **MIME type confusion:** Ako se MIME type (`"audio/mpeg"`) promeni na jednom mestu, može doći do nedoslednosti — fajl može biti poslužen sa pogrešnim Content-Type, što može dovesti do problema sa bezbednošću (npr. ako se audio fajl posluži kao `text/html`, browser može pokušati da ga renderuje).

**3. Visoka Cognitive Complexity:**

- **Logičke greške u kritičnim funkcijama:** Složene funkcije (Complexity > 15) su teže za razumevanje i održavanje, što povećava verovatnoću grešaka. U `user_handler.go:154` (Complexity 30) i `auth_middleware.go:15` (Complexity 20) — kritične tačke za autentifikaciju — visoka složenost može maskirati logičke greške koje napadač može iskoristiti (npr. propuštanje provere, pogrešna logika autorizacije, edge case-ovi koji nisu pokriveni).

- **Teškoća u code review-u:** Visoka složenost otežava code review, što povećava verovatnoću da se propuste sigurnosni problemi. Napadač može iskoristiti edge case-ove koji nisu uočeni tokom review-a.

**4. Nizak code coverage (0.0% na svim servisima):**

- **Nedetektovane regresije:** Bez testova, promene u kodu mogu uvesti nove ranjivosti koje neće biti detektovane. Napadač može iskoristiti regresije koje su uveđene tokom refaktorisanja ili dodavanja novih funkcionalnosti.

- **Nepokriveni edge case-ovi:** Bez testova, edge case-ovi (npr. granične vrednosti, null pointer dereferences, race conditions) mogu ostati neotkriveni i eksploatisani od strane napadača.

**5. Visok procenat duplikata (posebno u user-service handler direktorijumu — 17.1%):**

- **Propagacija grešaka:** Ako se greška uveđe u duplirani kod, propagira se na sva mesta gde se taj kod koristi. Napadač može iskoristiti grešku na svim instancama dupliranog koda.

- **Teškoća u održavanju:** Visok procenat duplikata otežava održavanje i refaktorisanje, što povećava verovatnoću da se uveđu nove ranjivosti tokom izmena.

---

### 6.4 Kako prevazići identifikovane ranjivosti

Na osnovu SonarQube Issues i Security Hotspots analize, evo konkretnih preporuka za prevazilaženje identifikovanih problema:

#### 1. Refaktorisanje dupliranih literala u konstante

**Prioritet: VISOK** — utiče na 17 od 20 issues.

**Za svaki servis, kreirati centralizovane konstante:**

**content-service:**
```go
// U handler/content_handler.go ili u poseban constants.go
const (
    ErrArtistIDRequired = "artist id is required"
    ErrInvalidInput = "invalid or potentially malicious input detected"
)

// U repository/content_repository.go
const (
    MongoOptionKey = "$options"
    MongoRegexKey = "$regex"
)
```

**user-service:**
```go
// U handler/user_handler.go
const HeaderXUserID = "X-User-ID"

// U service/user_service.go
const ErrUserNotFound = "user not found"
```

**notifications-service:**
```go
// U handler/notification_handler.go ili u poseban security/constants.go
const ErrInvalidMaliciousInput = "invalid or potentially malicious input detected"
```

**storage-service:**
```go
// U handler/storage_handler.go
const (
    ErrTrackIDRequired = "track_id is required"
    HeaderContentType = "Content-Type"
    HeaderContentLength = "Content-Length"
    HeaderAcceptRanges = "Accept-Ranges"
)

// U hdfs/client.go
const (
    ErrTrackNotFound = "track not found: %s"
    ErrFailedToStatFile = "failed to stat file: %w"
    MIMETypeAudioMPEG = "audio/mpeg"
)
```

**subscriptions-service:**
```go
// U handler/subscription_handler.go
const ErrUserNotAuthenticated = "user not authenticated"

// U repository/subscription_repository.go
const ErrFailedToDecodeSubscriptions = "failed to decode subscriptions: %w"
```

**Akcije:**
- Zameniti sve pojave dupliranih literala sa konstantama.
- Razmotriti kreiranje centralizovanog security error handling modula koji koristi konstante i obezbeđuje konzistentno logovanje i response za sve slučajeve malicioznog inputa.
- Nakon izmene, ponoviti SonarQube sken da se potvrdi da su issues rešeni.

#### 2. Smanjenje Cognitive Complexity

**Prioritet: VISOK** — utiče na 4 issues u user-service (kritične funkcije za autentifikaciju).

**Refaktorisanje složenih funkcija:**

**`handler/user_handler.go:154` (Complexity 30):**
- Podeliti funkciju u manje funkcije sa jasnom odgovornošću.
- Izvući zajedničke delove u helper funkcije.
- Koristiti early returns da se smanji ugnježdenost.

**`middleware/auth_middleware.go:15` (Complexity 20):**
- Izvući validaciju tokena u posebnu funkciju.
- Izvući proveru autorizacije u posebnu funkciju.
- Koristiti strategy pattern za različite tipove autentifikacije.

**`service/user_service.go:426` (Complexity 17):**
- Podeliti funkciju u manje funkcije.
- Izvući validaciju i business logiku u posebne funkcije.

**`utils/password_validator.go:8` (Complexity 16):**
- Podeliti validaciju lozinke u manje funkcije (npr. `validateLength`, `validateComplexity`, `validateCommonPasswords`).

**Akcije:**
- Refaktorisati funkcije da imaju Complexity ≤ 15.
- Dodati unit testove za refaktorisane funkcije da se osigura da funkcionalnost nije promenjena.
- Nakon izmene, ponoviti SonarQube sken da se potvrdi da su issues rešeni.

#### 3. Dodavanje code coverage testova

**Prioritet: KRITIČAN** — trenutno 0.0% coverage na svim servisima; Quality Gate zahteva ≥ 80%.

**Plan dodavanja testova:**

**Faza 1 — Unit testovi za kritične funkcije:**
- Autentifikacija/autorizacija (user-service, subscriptions-service)
- Input validacija (content-service, notifications-service)
- File handling (storage-service)
- Password validation (user-service)

**Faza 2 — Integration testovi:**
- API endpoint-ovi (svi servisi)
- Database operations (svi servisi)
- External service calls (npr. HDFS u storage-service)

**Faza 3 — End-to-end testovi:**
- Kompletni user flow-ovi
- Cross-service komunikacija

**Akcije:**
- Kreirati `*_test.go` fajlove za svaki modul.
- Koristiti Go testing framework (`testing` package) i mock biblioteke (npr. `testify/mock`).
- Integrisati testove u CI/CD pipeline da se automatski pokreću pre merge-a.
- Postaviti prag coverage-a (npr. 80%) u SonarQube Quality Gate.
- Nakon dodavanja testova, ponoviti SonarQube sken da se potvrdi da je coverage povećan.

#### 4. Smanjenje duplikata koda

**Prioritet: SREDNJI** — posebno kritično za user-service handler direktorijum (17.1% duplikata).

**Strategija smanjenja duplikata:**

**user-service handler direktorijum:**
- Izvući zajedničke delove u helper funkcije ili middleware.
- Koristiti generičke funkcije za zajedničke operacije (npr. error handling, response formatting).
- Refaktorisati duplirane blokove koda u reusable komponente.

**content-service:**
- Refaktorisati duplikate u `content_handler.go` (13.3% duplikata) — izvući zajedničke delove u funkcije ili konstante.

**Akcije:**
- Identifikovati duplirane blokove koda pomoću SonarQube Duplications tab-a.
- Refaktorisati duplikate u reusable komponente.
- Nakon izmene, ponoviti SonarQube sken da se potvrdi da su duplikati smanjeni.

#### 5. Praćenje i održavanje

**Akcije:**
- Redovno pokretanje SonarQube skenova (npr. pre svakog merge-a ili dnevno).
- Praćenje Quality Gate-a — blokirati merge ako Quality Gate padne.
- Code review fokusiran na:
  - Duplikovane literale (posebno security-relevantni)
  - Cognitive Complexity (posebno za kritične funkcije)
  - Code coverage (osigurati da novi kod ima testove)
- Automatizacija: integrisati SonarQube u CI/CD pipeline da automatski proverava Quality Gate i blokira merge ako ne prođe.

---

### 6.5 Kako se zaštititi od eksploatacije

Zaštita od eksploatacije identifikovanih ranjivosti zahteva kombinaciju **preventivnih mera** (SonarQube skenovi, code review, testovi) i **reaktivnih mera** (monitoring, incident response), povezanih sa postojećim kontrolama iz sekcija 1–6.

#### 1. Preventivne mere — SonarQube integracija

**Redovno pokretanje SonarQube skenova:**

- **Pre merge-a:** Automatski pokretati SonarQube sken za svaki pull request. Blokirati merge ako Quality Gate padne ili ako se uveđu novi Security/Reliability issues.
- **Dnevno/nedeljno:** Pokretati skenove za sve servise da se otkriju issues koji su možda propušteni tokom development-a.
- **Pre release-a:** Obavezno pokretati skenove pre svakog release-a i osigurati da su svi kritični issues rešeni.

**Praćenje Quality Gate-a:**

- **Postaviti Quality Gate kriterijume:**
  - Security: 0 issues (Critical, High, Medium)
  - Reliability: 0 issues (Critical, High)
  - Maintainability: ≤ 10 issues (High) — trenutno 20, cilj smanjiti na ≤ 10
  - Coverage: ≥ 80% — trenutno 0%, cilj postepeno povećati
  - Duplications: ≤ 3% — trenutno 0–4.25%, osigurati da ne prelazi 3%
- **Blokirati merge ako Quality Gate padne:** Integrisati SonarQube u CI/CD pipeline (npr. GitHub Actions, GitLab CI) da automatski proverava Quality Gate i blokira merge ako ne prođe.


#### 2. Preventivne mere — razvoj i testiranje

**Dodavanje testova za veći coverage:**

- **Unit testovi:** Pokrivati kritične funkcije (autentifikacija, validacija, file handling) sa unit testovima. Cilj: ≥ 80% coverage na svim servisima.
- **Integration testovi:** Pokrivati API endpoint-ove i database operations sa integration testovima.
- **Security testovi:** Dodati testove za edge case-ove (npr. maliciozni input, invalid tokens, unauthorized access) da se osigura da se ranjivosti ne uveđu tokom refaktorisanja.

**Smanjenje duplikata:**

- **Refaktorisanje dupliranih blokova:** Identifikovati duplirane blokove koda pomoću SonarQube Duplications tab-a i refaktorisati ih u reusable komponente.
- **Praćenje Duplications metrike:** Redovno praćenje Duplications metrike po direktorijumu; posebno kritično za user-service handler direktorijum (17.1% duplikata).


#### 3. Reaktivne mere — monitoring i incident response

**Centralizovano logovanje i monitoring:**

- **Integracija sa postojećim logging sistemom (sekcija 5 — Security Roadmap):** Centralizovati logove iz svih servisa u centralni store (npr. ELK, Loki, SIEM) da se podrži detekcija, alerting i incident response.
- **Logovanje security-relevantnih događaja:**
  - Autentifikacione greške (npr. `"user not authenticated"`, invalid tokens)
  - Input validation greške (npr. `"invalid or potentially malicious input detected"`)
  - Autorizacione greške (npr. unauthorized access attempts)
  - Rate limit hits (DoS mitigation)
- **Alerting:** Postaviti alertove za:
  - Neobične autentifikacione greške (npr. više od X neuspešnih pokušaja u kratkom vremenu)
  - Detekciju malicioznog inputa (npr. SQL injection, XSS patterns)
  - Neautorizovane pristupe (npr. pokušaji pristupa admin endpoint-ima)

**Incident response:**

- **Procedura za incident response:** Definirati proceduru za rukovanje sigurnosnim incidentima (npr. detekcija ranjivosti, eksploatacija, false positive).
- **Povezivanje sa SonarQube nalazima:** Ako se detektuje eksploatacija ranjivosti koja je identifikovana u SonarQube-u, prioritizovati rešavanje tog issue-a.

#### 4. Autentifikacija i autorizacija:

- **JWT validacija:** Osigurati da se JWT validacija izvršava konzistentno na svim endpoint-ima (refaktorisati duplikovane literale kao `"X-User-ID"`, `"user not authenticated"` u konstante).
- **RBAC enforcement:** Osigurati da se RBAC provere izvršavaju konzistentno (refaktorisati funkcije sa visokom Cognitive Complexity u auth middleware i handler slojevima).

#### 5. Input validacija:

- **Konzistentna validacija malicioznog inputa:** Osigurati da se validacija malicioznog inputa izvršava konzistentno na svim endpoint-ima (refaktorisati duplikovane literale kao `"invalid or potentially malicious input detected"` u konstante).
- **XSS i SQL injection zaštita:** Osigurati da se XSS i SQL injection pattern checks izvršavaju konzistentno (dodati testove da se osigura da se ranjivosti ne uveđu tokom refaktorisanja).

#### 6. Dos mitigation

- **Rate limiting:** Osigurati da se rate limiting izvršava konzistentno na svim endpoint-ima (dodati testove za rate limiting scenarije).
