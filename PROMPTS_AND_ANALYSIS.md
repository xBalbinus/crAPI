# crAPI Analysis Prompts & Vulnerability Assessment

---

## Part 1: Simplified Prompt (Non-Security Focused)

### For General Code Review / Issue Identification

```markdown
**System/Role:** You are a Senior Software Engineer specializing in Microservices Architecture and API Development.

**Context:**
You are reviewing the source code of a microservice application. This application uses multiple services communicating via REST APIs. Your goal is to identify code quality issues, bugs, and potential problems while minimizing false positives.

**Instructions:**

1.  **Analyze** the provided code structure, API endpoints, and data flow.

2.  **Scan** specifically for common code issues, including but not limited to:

    - **Input Validation:** Is user input properly validated before use?
    - **Error Handling:** Are errors caught and handled appropriately?
    - **Resource Management:** Are database connections, file handles, and HTTP connections properly managed?
    - **Code Quality:** Are there code smells, anti-patterns, or maintainability concerns?
    - **Data Consistency:** Could race conditions or inconsistent state occur?

3.  **Distinguish** between:

    - _Single Service Issues:_ Problems contained entirely within one service.
    - _Inter-service Issues:_ Problems that arise from service interactions (e.g., missing validation on internal API responses, timeout handling).

4.  **Output Format:**
    Return your findings in a Markdown table with the following columns:
        | Severity | Description | Type | Affected Files | Location | ID | Short Title |

**Constraint:** If an issue is suspected but the code context is incomplete (e.g., validation might be in middleware not shown), flag it as "Potential" rather than a definite bug.
```

---

## Part 2: Original Security Prompt (For Reference)

```markdown
**System/Role:** You are a Senior Application Security Engineer and Penetration Tester specializing in Microservices and API Security.

**Context:**
You are analyzing the source code of a deliberately vulnerable microservice application (DVMS). This service interacts with other services via REST/gRPC. Your goal is to identify valid security vulnerabilities while minimizing false positives.

**Instructions:**

1.  **Analyze** the provided code structure, API endpoints, and data flow.

2.  **Scan** specifically for the **OWASP API Security Top 10 (2023)** risks, including but not limited to:

    - **API1:2023 Broken Object Level Authorization (BOLA/IDOR):** Can User A access User B's resources by changing an ID?
    - **API2:2023 Broken Authentication:** Are tokens validated? Is there a lack of protection against brute force?
    - **API3:2023 Broken Object Property Level Authorization:** Is there excessive data exposure (returning full JSON objects) or Mass Assignment?
    - **API7:2023 Server Side Request Forgery (SSRF):** Does the service fetch URLs based on user input?
    - **API10:2023 Unsafe Consumption of APIs:** Does this service trust input from other microservices too implicitly?

3.  **Distinguish** between:

    - _Single Service Flaws:_ Issues contained entirely within this file.
    - _Inter-service Flaws:_ Issues that arise because this service trusts data from another service (look for missing validation on internal API calls).

4.  **Output Format:**
    Return your findings in a strict Markdown table with the following columns:
        | Severity | Description | Type | Affected Files | Location | Unique ID | Short Title |

**Constraint:** If a vulnerability is suspected but the code is incomplete (e.g., verification logic might be in middleware not shown), flag it as "Potential" rather than a definite bug.
```

---

## Part 3: Security Vulnerability Analysis Results

### OWASP API Security Top 10 (2023) Findings

| Severity     | Description                                                                                                                                                                       | Type                | Affected Files                                                                | Location                                        | Unique ID | Short Title                    |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------- | --------- | ------------------------------ |
| **Critical** | Vehicle location endpoint accepts any UUID without ownership verification. Any authenticated user can access another user's vehicle location by guessing/enumerating vehicle IDs. | Single Service Flaw | `services/identity/src/main/java/com/crapi/controller/VehicleController.java` | Line 122 (`getLocationBOLA`)                    | CRAPI-001 | BOLA - Vehicle Location        |
| **Critical** | Mechanic report endpoint only validates report_id format, not ownership. Any authenticated user can view any service report.                                                      | Single Service Flaw | `services/workshop/crapi/mechanic/views.py`                                   | Line 214-244 (`GetReportView`)                  | CRAPI-002 | BOLA - Mechanic Reports        |
| **Critical** | OTP validation endpoint `/api/auth/v2/check-otp` has no rate limiting or attempt tracking. Attacker can brute force 4-digit OTP.                                                  | Single Service Flaw | `services/identity/src/main/java/com/crapi/controller/AuthController.java`    | Line 127 (`checkOtp`)                           | CRAPI-003 | Broken Auth - OTP Brute Force  |
| **Critical** | SQL injection via string concatenation in coupon validation. User-controlled `coupon_code` directly concatenated into SQL query.                                                  | Single Service Flaw | `services/workshop/crapi/shop/views.py`                                       | Line 386-394 (`ApplyCouponView`)                | CRAPI-004 | SQL Injection                  |
| **Critical** | SSRF vulnerability in contact mechanic. User controls the `mechanic_api` URL which is fetched server-side without URL validation.                                                 | Single Service Flaw | `services/workshop/crapi/merchant/views.py`                                   | Line 84-92 (`ContactMechanicView`)              | CRAPI-005 | SSRF                           |
| **High**     | NoSQL injection in coupon validation. User-supplied BSON map directly passed to MongoDB query without sanitization.                                                               | Single Service Flaw | `services/community/api/controllers/coupon_controller.go`                     | Line 88-94 (`ValidateCoupon`)                   | CRAPI-006 | NoSQL Injection                |
| **High**     | Admin video deletion endpoint lacks proper authorization. Any authenticated user can delete any video by changing `video_id`.                                                     | Single Service Flaw | `services/identity/src/main/java/com/crapi/controller/ProfileController.java` | Line 129 (`deleteVideoBOLA`)                    | CRAPI-007 | BFLA - Admin Delete            |
| **High**     | Order update endpoint allows status change to "RETURNED" triggering refund without verification of actual return. Mass assignment vulnerability.                                  | Single Service Flaw | `services/workshop/crapi/shop/views.py`                                       | Line 219-259 (`OrderControlView.put`)           | CRAPI-008 | Mass Assignment - Order Status |
| **High**     | JWT tokens parsed with `ParseUnverified` function, allowing token forgery if attacker controls claims.                                                                            | Single Service Flaw | `services/community/api/auth/token.go`                                        | Line 81                                         | CRAPI-009 | JWT - Unverified Parsing       |
| **High**     | Shell injection in video conversion. The `conversion_params` from database is executed without sanitization.                                                                      | Single Service Flaw | `services/identity/src/main/java/com/crapi/controller/ProfileController.java` | Line 146 (requires ENABLE_SHELL_INJECTION=true) | CRAPI-010 | Shell Injection                |
| **High**     | Video internal properties (`conversion_params`) exposed in API response which can be modified for shell injection.                                                                | Single Service Flaw | `services/identity/src/main/java/com/crapi/controller/ProfileController.java` | Line 42-52                                      | CRAPI-011 | Excessive Data Exposure        |
| **Medium**   | CSRF protection disabled globally in Spring Security configuration.                                                                                                               | Single Service Flaw | `services/identity/src/main/java/com/crapi/config/WebSecurityConfig.java`     | Line 98                                         | CRAPI-012 | CSRF Disabled                  |
| **Medium**   | Service requests by VIN endpoint lacks authentication. Anyone can view service requests for any vehicle if they know the VIN.                                                     | Single Service Flaw | `services/workshop/crapi/merchant/views.py`                                   | Line 166 (`UserServiceRequestsView.get`)        | CRAPI-013 | Unauthenticated Access         |
| **Medium**   | Order GET endpoint lacks authentication. Anyone can view order details including payment info if they know order ID.                                                              | Single Service Flaw | `services/workshop/crapi/shop/views.py`                                       | Line 109-165 (`OrderControlView.get`)           | CRAPI-014 | Unauthenticated Access         |
| **Medium**   | Email token login allows authentication bypass if token is predictable or leaked. Token generation may be weak.                                                                   | Single Service Flaw | `services/identity/src/main/java/com/crapi/controller/AuthController.java`    | Line 169 (`loginWithTokenV2`)                   | CRAPI-015 | Broken Auth - Weak Token       |
| **Medium**   | Workshop service trusts Identity service JWT validation without additional verification. If Identity is compromised, Workshop is also compromised.                                | Inter-service Flaw  | `services/workshop/utils/jwt.py`                                              | Line 52-62                                      | CRAPI-016 | Unsafe API Consumption         |
| **Medium**   | Community service validates JWT by calling Identity service with `verify=False` (TLS disabled), allowing MITM attacks.                                                            | Inter-service Flaw  | `services/community/api/auth/token.go`                                        | Line 56                                         | CRAPI-017 | TLS Verification Disabled      |
| **Medium**   | Rate limiting for contact mechanic repeat requests is client-controlled (`number_of_repeats` up to 100). Enables DoS amplification.                                               | Single Service Flaw | `services/workshop/crapi/merchant/views.py`                                   | Line 69-80                                      | CRAPI-018 | DoS - Repeat Requests          |
| **Low**      | Private keys committed to repository (certs/\*.key in multiple services).                                                                                                         | Single Service Flaw | `services/*/certs/server.key`                                                 | All services                                    | CRAPI-019 | Hardcoded Secrets              |
| **Low**      | All Dockerfiles run as root (no USER directive). Container escape could give root access.                                                                                         | Single Service Flaw | All Dockerfiles                                                               | All services                                    | CRAPI-020 | Docker Security                |
| **Low**      | HTTP requests made without timeout, can lead to resource exhaustion.                                                                                                              | Single Service Flaw | Multiple Python files                                                         | Various                                         | CRAPI-021 | Missing Timeouts               |

---

## Part 4: Inter-Service Communication Security Analysis

### Trust Relationships

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          TRUST BOUNDARY DIAGRAM                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  EXTERNAL (Untrusted)          INTERNAL (Trusted?)                          │
│  ─────────────────────         ─────────────────────                        │
│                                                                              │
│  ┌─────────────┐               ┌─────────────────┐                          │
│  │   Browser   │───────────────│    crapi-web    │                          │
│  │  (User)     │   HTTPS       │  (Nginx Proxy)  │                          │
│  └─────────────┘               └────────┬────────┘                          │
│                                         │                                    │
│                    ┌────────────────────┼────────────────────┐              │
│                    │                    │                    │              │
│                    ▼                    ▼                    ▼              │
│         ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│         │  crapi-identity  │  │ crapi-community  │  │  crapi-workshop  │   │
│         │                  │  │                  │  │                  │   │
│         │  Issues JWT      │◄─┤  Validates JWT   │  │  Validates JWT   │   │
│         │  tokens          │  │  via HTTP call   │  │  via HTTP call   │   │
│         └──────────────────┘  │  (TLS DISABLED!) │  │  (TLS DISABLED!) │   │
│                 ▲             └──────────────────┘  └────────┬─────────┘   │
│                 │                                            │              │
│                 │                          ┌─────────────────┘              │
│                 │                          ▼                                │
│                 │             ┌─────────────────────────────┐              │
│                 │             │  api.mypremiumdealership    │              │
│                 │             │  (External Payment Gateway) │              │
│                 │             │  Called with TLS DISABLED!  │              │
│                 │             └─────────────────────────────┘              │
│                 │                                                           │
│  ⚠️ VULNERABILITIES:                                                        │
│  1. TLS verification disabled between services (MITM possible)             │
│  2. Services implicitly trust JWT claims without re-verification           │
│  3. External payment gateway called without TLS verification               │
│  4. No service mesh or mutual TLS between microservices                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow Security Concerns

| Flow              | From               | To               | Security Issue                       |
| ----------------- | ------------------ | ---------------- | ------------------------------------ |
| JWT Validation    | Community/Workshop | Identity         | TLS disabled (`verify=False`)        |
| User Data         | Identity           | Community        | Trusted without validation           |
| Payment Request   | Workshop           | External Gateway | TLS disabled, credentials in transit |
| Coupon Lookup     | Workshop           | MongoDB          | NoSQL injection possible             |
| Report Generation | Workshop           | Filesystem       | Path traversal possible              |

---

## Part 5: Scanner Installation Quick Reference

```bash
# === SCANNER INSTALLATION ===

# Semgrep (Multi-language SAST - RECOMMENDED)
brew install semgrep  # macOS
# or: pip install semgrep

# Bandit (Python-specific)
pip install bandit
# or use virtual env: python3 -m venv .venv && source .venv/bin/activate && pip install bandit

# npm audit (Built into npm for JS/TS)
# Already available with npm

# CodeQL (GitHub's SAST)
brew install codeql  # macOS
# or download from: https://github.com/github/codeql-action/releases

# Gosec (Go-specific)
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Trivy (Container scanning)
brew install trivy  # macOS

# === RUNNING SCANS ===

cd /path/to/crAPI

# Semgrep - all languages
semgrep --config=auto services/

# Bandit - Python only
bandit -r services/workshop/ services/chatbot/

# npm audit - JS/TS only
cd services/web && npm audit

# Gosec - Go only
cd services/community && gosec ./...

# CodeQL - requires database creation first
codeql database create codeql-db --language=java --source-root=services/identity
codeql database analyze codeql-db --format=sarif-latest --output=results.sarif
```

---

## Summary

This document provides:

1. **Simplified prompt** - For general code quality review (non-security)
2. **Original security prompt** - For security-focused vulnerability analysis
3. **Complete vulnerability table** - 21 identified vulnerabilities mapped to OWASP API Top 10
4. **Inter-service security analysis** - Trust boundaries and communication flows
5. **Scanner installation guide** - Quick reference for security tools
