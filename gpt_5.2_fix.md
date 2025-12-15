# gpt_5.2.csv Fixes (Dec 2025)

This file documents concrete remediations applied in the repo for each issue listed in `gpt_5.2.csv`.

## CRAPI-API2-001 — Unsigned JWT Accepted (Workshop)

- **Fix**: Verify JWT **signature** using Identity’s JWKS (RS256) instead of decoding with `verify_signature=False`. Removed TLS verification disable.
- **Files changed**:
  - `services/workshop/utils/jwt.py`
  - `services/workshop/crapi_site/settings.py` (added `IDENTITY_JWKS`)
- **Notes**:
  - Requires Identity JWKS endpoint to be reachable at `/identity/api/auth/jwks.json` (HTTP or HTTPS depending on `TLS_ENABLED`).

## CRAPI-API2-002 — Unsigned JWT + Token-in-URL (Community)

- **Fix**:
  - Removed acceptance of tokens via URL query `?token=` (token must come from `Authorization: Bearer ...`).
  - Implemented **RS256 signature verification** using Identity `/identity/api/auth/jwks.json` (cached keys; no `ParseUnverified`).
  - Removed global TLS “trust all” behavior (`InsecureSkipVerify`) and avoided mutating `http.DefaultTransport`.
- **Files changed**:
  - `services/community/api/auth/token.go`
  - `services/community/api/middlewares/middlewares.go`

## CRAPI-API1-001 — Global Auth Context (Concurrency)

- **Fix**: Removed package-level globals (`autherID`, `nickname`, `userEmail`, etc.) and replaced with **request-scoped** `AuthorContext` stored on `context.Context`.
- **Files changed**:
  - `services/community/api/models/user.go`
  - `services/community/api/models/post.go`
  - `services/community/api/middlewares/middlewares.go`
  - `services/community/api/controllers/post_controller.go`
  - `services/community/api/seed/seeder.go`

## CRAPI-API1-002 — Unauthenticated Order Read (IDOR)

- **Fix**:
  - Added `@jwt_auth_required` to `OrderControlView.get`.
  - Enforced **ownership**: authenticated user must match `order.user`.
- **Files changed**:
  - `services/workshop/crapi/shop/views.py`

## CRAPI-API10-001 — Insecure Payment Gateway Call (verify=False)

- **Fix**: Payment gateway call now uses `verify=True` (no `verify=False`).
- **Files changed**:
  - `services/workshop/crapi/shop/views.py`

## CRAPI-API1-003 — Unauthenticated Service Request Read (IDOR)

- **Fix**:
  - Added `@jwt_auth_required` to `ServiceRequestView.get`.
  - Enforced access:
    - Mechanics can only read requests **assigned to them**.
    - Users can only read requests for vehicles they **own**.
    - Admin allowed.
- **Files changed**:
  - `services/workshop/crapi/mechanic/views.py`

## CRAPI-API1-004 — Mechanic Cross-Request IDOR

- **Fix**:
  - `ServiceCommentView.post/get`: mechanics can only comment/read for **assigned** requests; users can only read for **owned** vehicles; admin allowed.
  - `ServiceRequestView.put`: only mechanic/admin, and mechanic must be **assigned**.
- **Files changed**:
  - `services/workshop/crapi/mechanic/views.py`

## CRAPI-API7-001 — SSRF via mechanic_api + Auth Forward

- **Fix**:
  - Eliminated outbound request to user-supplied `mechanic_api` URL (removes SSRF and auth-token forwarding).
  - `contact_mechanic` now creates the `ServiceRequest` **locally** (no external HTTP call).
  - `mechanic_api` kept as optional/deprecated input for backward compatibility but **ignored**.
- **Files changed**:
  - `services/workshop/crapi/merchant/views.py`
  - `services/workshop/crapi/merchant/serializers.py`

## CRAPI-API1-005 — Unauthenticated VIN→Service Requests (IDOR)

- **Fix**:
  - Added `@jwt_auth_required` to `UserServiceRequestsView.get`.
  - Enforced ownership: only return service requests for vehicles owned by the authenticated user.
- **Files changed**:
  - `services/workshop/crapi/merchant/views.py`

## CRAPI-API5-001 — Admin Users List Missing Role Check

- **Fix**: `/api/management/users/all` now requires `user.role == ADMIN`.
- **Files changed**:
  - `services/workshop/crapi/user/views.py`

## CRAPI-API6-001 — Coupon SQLi + Client-Controlled Credit Amount

- **Fix**:
  - Replaced raw SQL string concatenation with ORM `.exists()` check (no SQLi).
  - Credit increase now uses `coupon.amount` from coupon storage (server-side), ignoring client-supplied `amount`.
- **Files changed**:
  - `services/workshop/crapi/shop/views.py`
  - `services/workshop/crapi/shop/serializers.py` (amount is optional but ignored)

## CRAPI-API5-002 — Product Creation Missing Role Check

- **Fix**: `/api/shop/products` `POST` now requires `user.role == ADMIN`.
- **Files changed**:
  - `services/workshop/crapi/shop/views.py`

## CRAPI-API10-002 — Identity→Gateway Trust-All TLS

- **Fix**:
  - Removed “trust-all certs” and `NoopHostnameVerifier`.
  - RestTemplate now uses default TLS verification (JVM trust store / configured CA).
  - Ownership URL built via `UriComponentsBuilder` (safe query param handling).
- **Files changed**:
  - `services/identity/src/main/java/com/crapi/service/Impl/VehicleOwnershipServiceImpl.java`

## CRAPI-API3-001 — VIN Ownership PII + Hardcoded Basic Auth

- **Fix**:
  - Removed SSN and address fields from VIN ownership responses.
  - Removed hardcoded BasicAuth credentials; now reads `GATEWAY_BASIC_USER` and `GATEWAY_BASIC_PASS` from environment and fails closed if unset.
  - Uses constant-time compares for credential checks; returns `401` on missing/invalid auth.
- **Files changed**:
  - `services/gateway-service/main.go`
- **Deployment note**:
  - You must set `GATEWAY_BASIC_USER` and `GATEWAY_BASIC_PASS` in the gateway environment.
  - Workshop service now requires `API_GATEWAY_USERNAME` and `API_GATEWAY_PASSWORD` env vars (removed embedded creds in Django settings):
    - `services/workshop/crapi_site/settings.py`

## CRAPI-API10-003 — Chatbot Trusts Any TLS Cert

- **Fix**:
  - Enabled TLS verification for `httpx.Client` and `httpx.AsyncClient`.
  - Added `TLS_VERIFY` and optional `TLS_CA_BUNDLE` configuration.
- **Files changed**:
  - `services/chatbot/src/mcpserver/server.py`
  - `services/chatbot/src/mcpserver/config.py`

## CRAPI-API1-006 — Potential IDOR on Community Posts

- **Status**: **Needs product decision**.
- **Why**: Community post endpoints already require authentication via middleware (`SetMiddlewareAuthentication`), but the handler allows any authenticated user to fetch any post by ID.
- **Recommendation**:
  - If posts should be private: add per-object authorization (e.g., only author/admin can fetch by ID).
  - If posts are intended public-to-community: current behavior is acceptable; ensure no sensitive data is stored in posts.


