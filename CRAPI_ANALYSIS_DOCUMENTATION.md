# crAPI (Completely Ridiculous API) - Comprehensive Analysis Documentation

## Table of Contents
1. [Repository Overview](#1-repository-overview)
2. [Architecture & Data Flow Diagram](#2-architecture--data-flow-diagram)
3. [Service Communication Patterns](#3-service-communication-patterns)
4. [API Endpoints Reference](#4-api-endpoints-reference)
5. [Technology Stack](#5-technology-stack)
6. [Security Scanner Setup Guide](#6-security-scanner-setup-guide)

---

## 1. Repository Overview

### What is crAPI?
crAPI (**C**ompletely **R**idiculous **API**) is a deliberately vulnerable application designed to demonstrate and help learn about the **OWASP API Security Top 10** vulnerabilities. It simulates a B2C (Business-to-Customer) car servicing application.

### Business Domain
- **User Registration/Authentication**: Users can sign up, log in, and manage their accounts
- **Vehicle Management**: Users can register vehicles and manage vehicle details
- **Car Servicing**: Users can contact mechanics and request car service
- **E-Commerce/Shop**: Users can browse products, place orders, and apply coupons
- **Community Features**: Blog posts, comments, and social engagement
- **AI Chatbot**: LLM-powered assistant for user queries

### Repository Structure
```
crAPI/
├── deploy/                    # Deployment configurations
│   ├── docker/               # Docker Compose setup
│   ├── helm/                 # Kubernetes Helm charts
│   ├── k8s/                  # Kubernetes manifests
│   └── vagrant/              # Vagrant VM setup
├── docs/                     # Documentation
├── openapi-spec/             # OpenAPI specification
├── postman_collections/      # Postman API testing collections
└── services/                 # Microservice source code
    ├── chatbot/              # Python (Quart) - AI Chatbot service
    ├── community/            # Go (Gorilla Mux) - Blog/Community service
    ├── gateway-service/      # Go - API Gateway mock
    ├── identity/             # Java (Spring Boot) - Auth/User service
    ├── mailhog/              # Mail testing service
    ├── web/                  # React/TypeScript - Frontend SPA
    └── workshop/             # Python (Django) - Workshop/Shop service
```

---

## 2. Architecture & Data Flow Diagram

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                      EXTERNAL LAYER                                      │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│    ┌──────────────────┐                    ┌──────────────────┐                         │
│    │   Web Browser    │                    │  Mobile Client   │                         │
│    │    (Client)      │                    │   (Future)       │                         │
│    └────────┬─────────┘                    └────────┬─────────┘                         │
│             │                                       │                                    │
│             └───────────────────┬───────────────────┘                                    │
│                                 │                                                        │
│                                 ▼                                                        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                    INGRESS LAYER                                         │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│                        ┌──────────────────────────────────┐                             │
│                        │        crapi-web (Nginx)         │                             │
│                        │    Reverse Proxy + Static SPA    │                             │
│                        │     Ports: 8888 (HTTP), 8443     │                             │
│                        └─────────────┬────────────────────┘                             │
│                                      │                                                   │
│                    ┌─────────────────┼─────────────────┬─────────────────┐              │
│                    │                 │                 │                 │              │
│                    ▼                 ▼                 ▼                 ▼              │
│             /identity/        /community/       /workshop/         /chatbot/            │
│                                                                                          │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                 MICROSERVICES LAYER                                      │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐                │
│  │   crapi-identity   │  │  crapi-community   │  │  crapi-workshop    │                │
│  │   (Java/Spring)    │  │   (Go/Gorilla)     │  │  (Python/Django)   │                │
│  │     Port: 8080     │  │    Port: 8087      │  │    Port: 8000      │                │
│  │                    │  │                    │  │                    │                │
│  │  • User Auth       │  │  • Blog Posts      │  │  • Mechanic Mgmt   │                │
│  │  • JWT Tokens      │  │  • Comments        │  │  • Service Reqs    │                │
│  │  • Vehicle Mgmt    │  │  • Coupons         │  │  • Shop/Orders     │                │
│  │  • Profile/Videos  │  │    (MongoDB)       │  │  • Merchant API    │                │
│  │  • OTP/Email       │  │                    │  │                    │                │
│  └─────────┬──────────┘  └─────────┬──────────┘  └─────────┬──────────┘                │
│            │                       │                       │                            │
│            │                       │                       │                            │
│  ┌─────────┴───────────────────────┴───────────────────────┴─────────┐                 │
│  │                        crapi-chatbot (Python/Quart)               │                 │
│  │                             Port: 5002                            │                 │
│  │           • LLM-powered assistant • OpenAI integration            │                 │
│  └────────────────────────────────┬──────────────────────────────────┘                 │
│                                   │                                                     │
├───────────────────────────────────┼─────────────────────────────────────────────────────┤
│                             EXTERNAL SERVICES                                           │
├───────────────────────────────────┼─────────────────────────────────────────────────────┤
│                                   │                                                     │
│  ┌────────────────────┐           │           ┌────────────────────┐                   │
│  │      mailhog       │◄──────────┼───────────│  api.mypremium...  │                   │
│  │   (Email Testing)  │           │           │  (Gateway Mock)    │                   │
│  │    Port: 8025      │           │           │    HTTPS/443       │                   │
│  └────────────────────┘           │           └────────────────────┘                   │
│                                   │                                                     │
├───────────────────────────────────┼─────────────────────────────────────────────────────┤
│                               DATA LAYER                                                │
├───────────────────────────────────┼─────────────────────────────────────────────────────┤
│                                   │                                                     │
│  ┌────────────────────┐  ┌───────┴───────┐  ┌────────────────────┐                     │
│  │     PostgreSQL     │  │    MongoDB    │  │     ChromaDB       │                     │
│  │    Port: 5432      │  │  Port: 27017  │  │   Port: 8000       │                     │
│  │                    │  │               │  │                    │                     │
│  │  • Users           │  │  • Coupons    │  │  • Vector Store    │                     │
│  │  • Vehicles        │  │  • Blog Posts │  │  • Chatbot RAG     │                     │
│  │  • Orders          │  │  • Comments   │  │                    │                     │
│  │  • Service Reqs    │  │               │  │                    │                     │
│  └────────────────────┘  └───────────────┘  └────────────────────┘                     │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow Diagram (DFD) - Level 1

```
                                    ┌─────────────────────┐
                                    │      External       │
                                    │       User          │
                                    └──────────┬──────────┘
                                               │
                          ┌────────────────────┼────────────────────┐
                          │                    │                    │
                          ▼                    ▼                    ▼
                    ┌───────────┐       ┌───────────┐        ┌───────────┐
                    │  Browse   │       │   Auth    │        │   Shop    │
                    │   Posts   │       │  Actions  │        │  Actions  │
                    └─────┬─────┘       └─────┬─────┘        └─────┬─────┘
                          │                   │                    │
                          ▼                   ▼                    ▼
               ┌──────────────────────────────────────────────────────────────┐
               │                     crapi-web (Nginx)                        │
               │              (Reverse Proxy + React SPA)                     │
               └──────────────────────────┬───────────────────────────────────┘
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            │                             │                             │
            ▼                             ▼                             ▼
┌───────────────────────┐    ┌───────────────────────┐    ┌───────────────────────┐
│    IDENTITY SERVICE   │    │   COMMUNITY SERVICE   │    │   WORKSHOP SERVICE    │
│                       │    │                       │    │                       │
│  ┌─────────────────┐  │    │  ┌─────────────────┐  │    │  ┌─────────────────┐  │
│  │ User Register   │  │    │  │ Create Post     │  │    │  │ Contact         │  │
│  │ User Login      │  │    │  │ Add Comment     │  │    │  │ Mechanic        │  │
│  │ JWT Generation  │  │    │  │ View Posts      │  │    │  │                 │  │
│  └────────┬────────┘  │    │  └────────┬────────┘  │    │  └────────┬────────┘  │
│           │           │    │           │           │    │           │           │
│  ┌────────▼────────┐  │    │  ┌────────▼────────┐  │    │  ┌────────▼────────┐  │
│  │ Vehicle Mgmt    │  │    │  │ Coupon Validate │  │    │  │ Order Mgmt      │  │
│  │ Profile Mgmt    │  │    │  │ Coupon Create   │  │    │  │ Product Browse  │  │
│  │ OTP/Password    │  │    │  │                 │  │    │  │ Apply Coupon    │  │
│  └────────┬────────┘  │    │  └────────┬────────┘  │    │  └────────┬────────┘  │
│           │           │    │           │           │    │           │           │
└───────────┼───────────┘    └───────────┼───────────┘    └───────────┼───────────┘
            │                            │                            │
            ▼                            ▼                            ▼
    ┌───────────────┐           ┌───────────────┐           ┌───────────────┐
    │  PostgreSQL   │           │   MongoDB     │           │  PostgreSQL   │
    │               │           │               │           │  + MongoDB    │
    │  Users        │           │  Posts        │           │               │
    │  Vehicles     │           │  Comments     │           │  Orders       │
    │  OTPs         │           │  Coupons      │           │  Products     │
    │  Videos       │           │               │           │  ServiceReqs  │
    └───────────────┘           └───────────────┘           └───────────────┘
```

### Request Flow Sequence

```
User Request → crapi-web (Nginx) → Path-based Routing → Backend Service → Database
                    │
                    ├── /identity/*  → crapi-identity (Java/Spring) → PostgreSQL
                    ├── /community/* → crapi-community (Go)         → MongoDB
                    ├── /workshop/*  → crapi-workshop (Python)      → PostgreSQL + MongoDB
                    └── /chatbot/*   → crapi-chatbot (Python)       → MongoDB + ChromaDB
```

---

## 3. Service Communication Patterns

### 3.1 Inter-Service Communication

| Source Service | Target Service | Communication Type | Purpose |
|----------------|----------------|-------------------|---------|
| crapi-web | All services | HTTP REST (Reverse Proxy) | Route API requests |
| crapi-workshop | crapi-identity | HTTP REST (Internal) | JWT Validation |
| crapi-community | crapi-identity | HTTP REST (Internal) | JWT Validation via middleware |
| crapi-chatbot | crapi-identity | HTTP REST (Internal) | User authentication |
| crapi-workshop | api.mypremiumdealership.com | HTTPS REST | Payment processing (mock) |
| crapi-identity | mailhog | SMTP (1025) | Email sending |

### 3.2 Authentication Flow

```
┌──────────┐     1. Login Request      ┌──────────────────┐
│  Client  │ ───────────────────────►  │  crapi-identity  │
└──────────┘                           └────────┬─────────┘
     ▲                                          │
     │                                          │ 2. Validate credentials
     │                                          ▼
     │                                 ┌──────────────────┐
     │                                 │    PostgreSQL    │
     │                                 └────────┬─────────┘
     │                                          │
     │         3. Return JWT Token              │
     └──────────────────────────────────────────┘

┌──────────┐     4. API Request + JWT   ┌──────────────────┐
│  Client  │ ───────────────────────►   │    crapi-web     │
└──────────┘                            └────────┬─────────┘
                                                 │
                                                 │ 5. Route to service
                                                 ▼
                                        ┌──────────────────┐
                                        │  Target Service  │
                                        │  (validates JWT) │
                                        └──────────────────┘
```

### 3.3 JWT Token Flow
- **Identity Service** generates JWT tokens upon successful login
- Tokens are signed using keys from `/deploy/docker/keys/jwks.json`
- All backend services validate tokens independently
- Community service calls Identity service to extract user from token
- Workshop service uses custom `@jwt_auth_required` decorator

### 3.4 Database Access Patterns

| Service | PostgreSQL | MongoDB |
|---------|------------|---------|
| Identity | ✅ Users, Vehicles, OTPs, Videos | ❌ |
| Community | ✅ User lookup (cross-service) | ✅ Posts, Comments, Coupons |
| Workshop | ✅ Orders, Products, ServiceRequests | ✅ Coupons validation |
| Chatbot | ✅ (via Identity) | ✅ Chat sessions |

---

## 4. API Endpoints Reference

### 4.1 Identity Service (`/identity/`)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | No | User login, returns JWT |
| POST | `/api/auth/signup` | No | User registration |
| POST | `/api/auth/verify` | No | Verify JWT token |
| POST | `/api/auth/forget-password` | No | Generate OTP for password reset |
| POST | `/api/auth/v2/check-otp` | No | Validate OTP (vulnerable) |
| POST | `/api/auth/v3/check-otp` | No | Validate OTP (rate-limited) |
| POST | `/api/v2/user/login-with-token` | No | Login with email token |
| GET | `/api/v2/user/dashboard` | No | Get dashboard data |
| POST | `/api/v2/vehicle/register_vehicle` | Yes | Register new vehicle |
| POST | `/api/v2/vehicle/add_vehicle` | Yes | Add vehicle details |
| GET | `/api/v2/vehicle/vehicles` | Yes | Get user's vehicles |
| GET | `/api/v2/vehicle/{carId}/location` | Yes | Get vehicle location (BOLA) |
| GET | `/api/v2/user/videos/{video_id}` | Yes | Get profile video |
| POST | `/api/v2/user/pictures` | Yes | Upload profile picture |
| POST | `/api/v2/user/videos` | Yes | Upload profile video |
| PUT | `/api/v2/user/videos/{video_id}` | Yes | Update video (mass assignment) |
| DELETE | `/api/v2/user/videos/{video_id}` | Yes | Delete video (BFLA hint) |
| DELETE | `/api/v2/admin/videos/{video_id}` | Yes | Admin delete video (BFLA) |
| GET | `/api/v2/user/videos/convert_video` | Yes | Convert video (shell injection) |

### 4.2 Community Service (`/community/`)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v2/community/posts/recent` | Yes | Get recent posts |
| GET | `/api/v2/community/posts/{postID}` | Yes | Get post by ID |
| POST | `/api/v2/community/posts` | Yes | Create new post |
| POST | `/api/v2/community/posts/{postID}/comment` | Yes | Add comment |
| POST | `/api/v2/coupon/new-coupon` | Yes | Create coupon |
| POST | `/api/v2/coupon/validate-coupon` | Yes | Validate coupon (NoSQL injection) |

### 4.3 Workshop Service (`/workshop/`)

**Mechanic APIs (`/api/mechanic/`)**
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `signup` | No | Mechanic registration |
| GET | `receive_report` | No | Receive service report |
| GET | `mechanic_report` | Yes | Get mechanic report (BOLA) |
| POST | `service_request/{id}/comment` | Yes | Add service comment |
| PUT | `service_request/{id}` | Yes | Update service request |
| GET | `service_requests` | Yes | Get all service requests |
| GET | `download_report` | No | Download report file |
| GET | `/` | Yes | List all mechanics |

**Merchant APIs (`/api/merchant/`)**
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `contact_mechanic` | Yes | Contact mechanic (SSRF) |
| GET | `service_requests/{vin}` | No | Get service requests by VIN |

**Shop APIs (`/api/shop/`)**
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `products` | Yes | List products |
| POST | `products` | Yes | Add product |
| GET | `orders/all` | Yes | Get all orders |
| POST | `orders` | Yes | Create order |
| PUT | `orders/{order_id}` | Yes | Update order (mass assignment) |
| GET | `orders/{order_id}` | No | Get order by ID |
| POST | `orders/return_order` | Yes | Return order |
| GET | `return_qr_code` | No | Get return QR code |
| POST | `apply_coupon` | Yes | Apply coupon (SQL injection) |

**Management APIs (`/api/management/`)**
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `users/all` | Yes | Get all users (admin) |

### 4.4 Chatbot Service (`/chatbot/`)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/` | No | Health check |
| POST | `/genai/init` | No | Initialize chatbot with API key |
| POST | `/genai/model` | No | Set LLM model |
| POST | `/genai/ask` | Yes | Send message to chatbot |
| GET | `/genai/state` | Yes | Get chatbot state |
| GET | `/genai/history` | Yes | Get chat history |
| POST | `/genai/reset` | Yes | Reset chat session |

---

## 5. Technology Stack

### 5.1 Backend Services

| Service | Language | Framework | Port |
|---------|----------|-----------|------|
| Identity | Java 17 | Spring Boot 3.x | 8080 |
| Community | Go 1.18+ | Gorilla Mux | 8087 |
| Workshop | Python 3.9+ | Django + DRF | 8000 |
| Chatbot | Python 3.9+ | Quart (async Flask) | 5002 |
| Gateway | Go | Custom | 443 |
| Web | TypeScript | React + Nginx | 80/443 |

### 5.2 Databases

| Database | Version | Purpose |
|----------|---------|---------|
| PostgreSQL | 14 | Primary relational data |
| MongoDB | 4.4 | Document store (posts, coupons) |
| ChromaDB | Latest | Vector embeddings for RAG |

### 5.3 Supporting Services

| Service | Purpose |
|---------|---------|
| Mailhog | Email testing/capture |
| OpenResty/Nginx | Reverse proxy, static files |

---

## 6. Security Scanner Setup Guide

### 6.1 Recommended Scanners

#### Option 1: Semgrep (Recommended - Multi-language)
```bash
# Install Semgrep
pip install semgrep

# Or via Homebrew (macOS)
brew install semgrep

# Run on the repository
cd /Users/the-x-machine/work/bu/research/crAPI
semgrep --config=auto services/

# Run with OWASP rules
semgrep --config=p/owasp-top-ten services/

# Run with security-audit rules
semgrep --config=p/security-audit services/
```

#### Option 2: CodeQL (GitHub's SAST)
```bash
# Install CodeQL CLI
# Download from: https://github.com/github/codeql-action/releases
# Or via Homebrew:
brew install codeql

# Initialize database (for Java)
cd /Users/the-x-machine/work/bu/research/crAPI/services/identity
codeql database create ../codeql-db-java --language=java

# Initialize database (for Python)
cd /Users/the-x-machine/work/bu/research/crAPI/services/workshop
codeql database create ../codeql-db-python --language=python

# Initialize database (for Go)
cd /Users/the-x-machine/work/bu/research/crAPI/services/community
codeql database create ../codeql-db-go --language=go

# Run analysis
codeql database analyze codeql-db-java --format=sarif-latest --output=results-java.sarif
```

#### Option 3: JavaScript-Specific Scanners

**ESLint Security Plugin:**
```bash
# Install locally in web service
cd /Users/the-x-machine/work/bu/research/crAPI/services/web
npm install --save-dev eslint-plugin-security

# Add to .eslintrc.json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"]
}

# Run
npx eslint src/ --ext .ts,.tsx,.js
```

**npm audit:**
```bash
cd /Users/the-x-machine/work/bu/research/crAPI/services/web
npm audit
npm audit --json > npm-audit-results.json
```

**Snyk (requires account):**
```bash
npm install -g snyk
snyk auth
snyk test services/web
snyk code test services/
```

#### Option 4: Bandit (Python-specific)
```bash
pip install bandit

# Run on workshop service
bandit -r services/workshop/ -f json -o bandit-results.json

# Run on chatbot service
bandit -r services/chatbot/ -f json -o bandit-chatbot-results.json
```

#### Option 5: Gosec (Go-specific)
```bash
# Install
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Run on community service
cd services/community
gosec -fmt=json -out=gosec-results.json ./...
```

#### Option 6: SpotBugs/FindSecBugs (Java-specific)
```bash
# Add to build.gradle.kts in identity service
plugins {
    id("com.github.spotbugs") version "5.0.14"
}

dependencies {
    spotbugsPlugins("com.h3xstream.findsecbugs:findsecbugs-plugin:1.12.0")
}

# Run
cd services/identity
./gradlew spotbugsMain
```

### 6.2 Quick Scanner Installation Script

```bash
#!/bin/bash
# scanner_install.sh

echo "Installing security scanners..."

# Semgrep (Multi-language)
pip install semgrep

# Bandit (Python)
pip install bandit

# Safety (Python dependencies)
pip install safety

# Gosec (Go)
go install github.com/securego/gosec/v2/cmd/gosec@latest

# npm audit is built-in to npm

echo "Installation complete!"
echo ""
echo "Run scans with:"
echo "  semgrep --config=auto services/"
echo "  bandit -r services/workshop/ services/chatbot/"
echo "  gosec ./services/community/..."
echo "  cd services/web && npm audit"
```

### 6.3 Running All Scanners

```bash
#!/bin/bash
# run_all_scans.sh

REPO_ROOT="/Users/the-x-machine/work/bu/research/crAPI"
RESULTS_DIR="$REPO_ROOT/scan_results"
mkdir -p "$RESULTS_DIR"

echo "=== Running Security Scans ==="

# Semgrep (all languages)
echo "[1/4] Running Semgrep..."
semgrep --config=auto "$REPO_ROOT/services/" \
  --json --output="$RESULTS_DIR/semgrep-results.json"

# Bandit (Python)
echo "[2/4] Running Bandit..."
bandit -r "$REPO_ROOT/services/workshop/" "$REPO_ROOT/services/chatbot/" \
  -f json -o "$RESULTS_DIR/bandit-results.json"

# Gosec (Go)
echo "[3/4] Running Gosec..."
cd "$REPO_ROOT/services/community"
gosec -fmt=json -out="$RESULTS_DIR/gosec-results.json" ./...

# npm audit (JavaScript)
echo "[4/4] Running npm audit..."
cd "$REPO_ROOT/services/web"
npm audit --json > "$RESULTS_DIR/npm-audit-results.json"

echo "=== Scans Complete ==="
echo "Results saved to: $RESULTS_DIR/"
```

---

## Summary

crAPI is a microservices-based deliberately vulnerable application demonstrating:
- **7 main services**: Web (React), Identity (Java), Community (Go), Workshop (Python), Chatbot (Python), Gateway (Go), Mailhog
- **3 databases**: PostgreSQL, MongoDB, ChromaDB
- **Path-based routing** through Nginx reverse proxy
- **JWT-based authentication** issued by Identity service
- **Cross-service communication** for token validation and data sharing
- **OWASP API Top 10 vulnerabilities** intentionally embedded for learning

The application uses a polyglot architecture to simulate real-world complexity while remaining lightweight enough to run on a single machine.

