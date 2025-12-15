# crAPI Security Scan Results

**Scan Date:** December 12, 2025  
**Scanners Used:** Semgrep 1.145.0, Bandit 1.9.2, npm audit

---

## Executive Summary

| Scanner         | Findings | Critical | High | Medium | Low |
| --------------- | -------- | -------- | ---- | ------ | --- |
| Semgrep         | 37       | 0        | 6    | 15     | 16  |
| Bandit (Python) | 22       | 0        | 5    | 6      | 11  |
| npm audit (JS)  | 13+      | 1        | 3    | 2      | 7+  |

---

## Semgrep Findings (37 Total)

### Security Issues by Category

#### 1. Hardcoded Secrets & Credentials (7 findings)

| File                                                    | Issue                                      |
| ------------------------------------------------------- | ------------------------------------------ |
| `services/chatbot/certs/server.key`                     | Private key detected in repository         |
| `services/community/certs/server.key`                   | Private key detected in repository         |
| `services/gateway-service/server.key`                   | Private key detected in repository         |
| `services/identity/src/main/resources/certs/server.key` | Private key detected in repository         |
| `services/web/certs/server.key`                         | Private key detected in repository         |
| `services/workshop/certs/server.key`                    | Private key detected in repository         |
| `services/chatbot/src/chatbot/chat_api.py:33,76`        | Logging potential secrets (OpenAI API Key) |

#### 2. TLS/SSL Security Issues (5 findings)

| File                                                     | Line | Issue                                 |
| -------------------------------------------------------- | ---- | ------------------------------------- |
| `services/community/api/auth/token.go`                   | 56   | Missing TLS MinVersion configuration  |
| `services/community/api/auth/token.go`                   | 56   | TLS certificate verification bypassed |
| `services/community/api/server.go`                       | 47   | Missing TLS MinVersion configuration  |
| `services/community/api/server.go`                       | 47   | TLS certificate verification bypassed |
| `services/identity/.../VehicleOwnershipServiceImpl.java` | 29   | Insecure hostname verifier            |

#### 3. JWT Security Issues (1 finding)

| File                                   | Line | Issue                                               |
| -------------------------------------- | ---- | --------------------------------------------------- |
| `services/community/api/auth/token.go` | 81   | JWT parsed without verification (`ParseUnverified`) |

#### 4. Web Security Issues (4 findings)

| File                                           | Line    | Issue                                       |
| ---------------------------------------------- | ------- | ------------------------------------------- |
| `services/identity/.../WebSecurityConfig.java` | 98      | CSRF protection disabled                    |
| `services/workshop/crapi/mechanic/views.py`    | 54      | `@csrf_exempt` decorator used               |
| `services/community/api/responses/json.go`     | 29      | Direct Fprintf to ResponseWriter (XSS risk) |
| `services/gateway-service/main.go`             | 107,150 | Direct write to ResponseWriter              |

#### 5. Insecure Random Number Generation (1 finding)

| File                               | Line | Issue                                      |
| ---------------------------------- | ---- | ------------------------------------------ |
| `services/gateway-service/main.go` | 9    | Using `math/rand` instead of `crypto/rand` |

#### 6. Docker Security (6 findings)

All Dockerfiles missing USER directive (running as root):

- `services/chatbot/Dockerfile`
- `services/community/Dockerfile`
- `services/gateway-service/Dockerfile`
- `services/identity/Dockerfile`
- `services/web/Dockerfile`
- `services/workshop/Dockerfile`

#### 7. Other Issues

| File                                            | Issue                                         |
| ----------------------------------------------- | --------------------------------------------- |
| `services/chatbot/src/mcpserver/__main__.py:15` | Flask running on 0.0.0.0                      |
| `services/workshop/crapi/mechanic/views.py:427` | Direct Jinja2 usage (template injection risk) |

---

## Bandit Findings (Python - 22 Total)

### HIGH Severity (5 findings)

| File                                                          | Line | Issue                                      |
| ------------------------------------------------------------- | ---- | ------------------------------------------ |
| `services/chatbot/src/mcpserver/server.py`                    | 41   | SSL verification disabled (`verify=False`) |
| `services/chatbot/src/mcpserver/server.py`                    | 74   | SSL verification disabled (`verify=False`) |
| `services/workshop/core/management/commands/seed_database.py` | 220  | SSL verification disabled                  |
| `services/workshop/crapi/merchant/views.py`                   | 91   | SSL verification disabled                  |
| `services/workshop/crapi/shop/views.py`                       | 148  | SSL verification disabled                  |
| `services/workshop/utils/jwt.py`                              | 54   | SSL verification disabled                  |

### MEDIUM Severity (6 findings)

| File                                         | Line | Issue                                      |
| -------------------------------------------- | ---- | ------------------------------------------ |
| `services/chatbot/src/mcpserver/__main__.py` | 15   | Binding to all interfaces (0.0.0.0)        |
| `services/chatbot/src/mcpserver/server.py`   | 93   | Binding to all interfaces                  |
| `services/workshop/crapi/merchant/views.py`  | 87   | HTTP request without timeout               |
| `services/workshop/crapi/shop/tests.py`      | 166  | **SQL Injection via string concatenation** |
| `services/workshop/crapi/shop/views.py`      | 389  | **SQL Injection via string concatenation** |
| `services/workshop/utils/jwt.py`             | 53   | HTTP request without timeout               |

### LOW Severity (11 findings)

- Insecure pseudo-random generators in seed_database.py (lines 152-154)
- Insecure pseudo-random generators in apps.py (lines 146-148)
- Hardcoded passwords in settings.py, helper.py

---

## npm audit Findings (JavaScript/TypeScript)

### CRITICAL (1 finding)

| Package     | Issue                                              |
| ----------- | -------------------------------------------------- |
| `form-data` | Uses unsafe random function for boundary selection |

### HIGH (3 findings)

| Package      | Issue                                              |
| ------------ | -------------------------------------------------- |
| `glob`       | Command injection via -c/--cmd                     |
| `jws`        | Improper HMAC signature verification               |
| `node-forge` | ASN.1 unbounded recursion, interpretation conflict |

### MODERATE (2 findings)

| Package              | Issue                        |
| -------------------- | ---------------------------- |
| `js-yaml`            | Prototype pollution in merge |
| `mdast-util-to-hast` | Unsanitized class attribute  |

---

## Intentional Vulnerabilities (OWASP API Top 10)

Based on code analysis, these **intentional vulnerabilities** are embedded for learning:

| ID  | Vulnerability                                     | Location                                   | Type                         |
| --- | ------------------------------------------------- | ------------------------------------------ | ---------------------------- | --------- |
| V1  | **BOLA** - Access other users' vehicle location   | `VehicleController.java:122`               | API1:2023                    |
| V2  | **BOLA** - Access other users' mechanic reports   | `GetReportView` in views.py                | API1:2023                    |
| V3  | **Broken Auth** - OTP brute force (no rate limit) | `AuthController.java:127` (`v2/check-otp`) | API2:2023                    |
| V4  | **Broken Auth** - Weak email token login          | `AuthController.java:169`                  | API2:2023                    |
| V5  | **Excessive Data Exposure**                       | Video internal properties exposed          | API3:2023                    |
| V6  | **Mass Assignment**                               | Order status update                        | `shop/views.py:219-259`      | API3:2023 |
| V7  | **SSRF**                                          | Contact mechanic URL fetch                 | `merchant/views.py:87`       | API7:2023 |
| V8  | **NoSQL Injection**                               | Coupon validation                          | `coupon_controller.go:94`    | Injection |
| V9  | **SQL Injection**                                 | Apply coupon                               | `shop/views.py:389`          | Injection |
| V10 | **BFLA**                                          | Admin video deletion                       | `ProfileController.java:129` | API5:2023 |
| V11 | **Rate Limiting**                                 | Contact mechanic repeat requests           | `merchant/views.py:69-80`    | API4:2023 |
| V12 | **Shell Injection**                               | Video conversion                           | `ProfileController.java:146` | Injection |
| V13 | **JWT Vulnerabilities**                           | Token parsing without verification         | `token.go:81`                | API2:2023 |

---

## Recommendations

### Immediate Actions

1. **Remove private keys from repository** - Use secrets management
2. **Enable TLS certificate verification** - Production must verify certs
3. **Add rate limiting** - All authentication endpoints
4. **Fix SQL injection** - Use parameterized queries
5. **Add timeouts to HTTP requests** - Prevent hanging connections

### Docker Security

1. Add `USER` directive to all Dockerfiles
2. Use multi-stage builds to reduce image size
3. Scan images with Trivy or similar

### Dependency Updates

1. Run `npm audit fix` in web service
2. Update vulnerable Go dependencies
3. Pin dependency versions

---

## Scan Commands Reference

```bash
# Semgrep (Multi-language)
semgrep --config=auto services/ --json --output=scan_results/semgrep-results.json

# Bandit (Python)
source .venv/bin/activate
bandit -r services/workshop/ services/chatbot/ -f json -o scan_results/bandit-results.json

# npm audit (JavaScript)
cd services/web && npm audit --json > scan_results/npm-audit-results.json

# Go security (if gosec installed)
cd services/community && gosec -fmt=json -out=scan_results/gosec-results.json ./...
```
