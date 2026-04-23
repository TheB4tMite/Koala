# Project Koala: Zero Trust for MCP

![Project Banner](https://img.shields.io/badge/Project-Koala-blueviolet?style=for-the-badge&logo=shield)
![Security Architecture](https://img.shields.io/badge/Architecture-ZTA-success?style=for-the-badge)
![Institution](https://img.shields.io/badge/Amrita_Vishwa_Vidyapeetham-Cybersecurity-blue?style=for-the-badge)

Project Koala is a Zero Trust Architecture (ZTA) implementation for Model Context Protocol (MCP) servers. Built as a 3rd-year B.Tech Cybersecurity course project at Amrita Vishwa Vidyapeetham, it applies rigorous **NIST SP 800-207** principles to AI Agents interacting with backend capabilities via MCP.

---

## Project Overview

As AI agents increasingly consume enterprise resources via the Model Context Protocol (MCP), relying on perimeter-based security is no longer sufficient. Project Koala introduces a resilient, microservice-based Zero Trust Architecture that shifts security from network boundaries to individual transaction flows. 

Every request is individually verified, cryptographically sealed, and dynamically authorized based on real-time continuous trust evaluations before being forwarded to the underlying MCP server.

---

## Architecture & Request Flow

```mermaid
sequenceDiagram
    participant A as Agent
    participant PEP as PEP (Gateway)
    participant PDP as PDP (Policy Engine)
    participant MCP as MCP Core
    
    A->>PEP: MCP Request (e.g., tools/call)
    PEP->>PEP: Compute payload hash
    PEP->>PDP: POST /authorize (SecurityContext)
    PDP->>PDP: Evaluate Trust Score
    
    alt Decision: PERMIT
        PDP-->>PEP: PERMIT
        PEP->>PEP: Sign SecurityContext (HMAC-SHA256)
        PEP->>MCP: Forward Request + X-Koala-Context
        MCP-->>PEP: Response
        PEP->>PEP: Egress Scrubbing
        PEP-->>A: MCP Response
    else Decision: CHALLENGE
        PDP-->>PEP: CHALLENGE
        PEP->>PEP: Park Request (In-flight)
        A->>PEP: POST /stepup/verify (Secondary Token)
        PEP->>PEP: Release Parked Request
        PEP->>MCP: Forward Request + X-Koala-Context
        MCP-->>PEP: Response
        PEP->>PEP: Egress Scrubbing
        PEP-->>A: MCP Response
    else Decision: DENY
        PDP-->>PEP: DENY
        PEP-->>A: 403 Forbidden / -32001
    end
```

---

## Core Components

The architecture relies on the strict separation of control and data planes across three distinct Docker containers:

1. **PEP (Policy Enforcement Point - Routing Layer):** Acts as the gateway and interceptor for all incoming MCP traffic. It intercepts requests, builds the security context, enforces step-up auth handling by temporarily parking requests, and acts as the egress point for scrubbing outgoing data.
2. **PDP (Policy Decision Point - Policy Engine):** Operates entirely out of band from the data plane. It evaluates requests against a continuous trust-scoring model, issuing real-time decisions (`PERMIT`, `CHALLENGE`, `DENY`), and securely logs the transaction using a tamper-evident hash-chain logger.
3. **MCP Core:** The core server executing the actual capabilities. Operates in a strict "fail-closed" posture, only accepting traffic that contains a cryptographically verified `SecurityContext` envelope from the PEP.

---

## Key Security Features

Project Koala bridges academic theory and production-grade security, implementing:

- **Cryptographic Context Sealing:** Every request payload is hashed and bound to a `SecurityContext` signed using HMAC-SHA256. This prevents request tampering and payload modification in transit.
- **Continuous Trust Evaluation:** Implements CARTA (Continuous Adaptive Risk and Trust Assessment) rate-limiting, dynamically calculating trust scores per subject based on request frequencies and behaviors over time windows.
- **Step-Up Authentication:** When trust scores drop into the `CHALLENGE` band, the PEP gracefully "parks" the in-flight request and waits for an out-of-band `stepup/verify` interaction. Once the secondary token is provided, the original request resumes.
- **Tamper-Evident Audit Logging:** Ensures non-repudiation by pushing transaction records into a PostgreSQL database linked by a cryptographic hash-chain, guaranteeing that logs cannot be quietly modified or deleted.

---

## Quick Start / Setup

### Prerequisites
- Docker and Docker Compose
- Python 3.9+ (For running the mock agent locally)

### Environment Setup
You can optionally define these environment variables, though sensible defaults are configured in `docker-compose.yml`:

```bash
# Signing Secret used between PEP and MCP Core
export KOALA_SIGNING_SECRET="koala_secret_dev"

# Token expected for step-up challenge flows
export KOALA_STEPUP_TOKEN="koala_admin_token"
```

### Running the Environment
Clone the repository and spin up the microservices:

```bash
git clone https://github.com/your-org/Koala.git
cd Koala
docker-compose up --build
```
This command builds and deploys the `pep` (port 8000), `pdp` (port 8181), and `mcp_core` (port 8080) services into an isolated bridge network (`zta_internal`).

---

## Testing the System

A `mock_agent.py` script is provided to demonstrate the Zero Trust features in action. It executes both a standard "Happy Path" and a simulated "Challenge Flow" that triggers rate-limiting.

1. Ensure the Docker containers are running.
2. Install HTTPX (used by the mock agent):
   ```bash
   pip install httpx
   ```
3. Run the mock agent:
   ```bash
   python agents/mock_agent.py
   ```

**What to expect:**
- The agent successfully initializes and calls `tools/list` and `tools/call`.
- It intentionally spams the PEP to trigger a drop in its trust score.
- The PDP responds with a `CHALLENGE` decision.
- The PEP parks the request and the mock agent immediately sends a `/stepup/verify` request.
- The parked request is securely released and fully executed.

---

## The Team

- **Anirudh** (Lead / Architecture)
- **Keerthan KK** (Developer)
- **Aaron Mathews** (Developer)

*Amrita Vishwa Vidyapeetham, 2026.*
