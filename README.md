README.md


# 🤝 Pramaan A2A — HandshakeOS

**A Proof-of-Authority Governance Extension for Agent-to-Agent Trust**

> A2A enables agents to talk. HandshakeOS decides whether they should trust and obey each other.

> **Security in the Agentic Future** — AI agents are powerful but they're also new attack surfaces. HandshakeOS provides monitoring frameworks, defense mechanisms, and trust architectures that keep agentic systems safe from prompt injection, identity spoofing, unauthorized access, and adversarial misuse.

Built with **LangChain**, **A2A SDK**, **AG-UI Protocol**, **FastAPI**, and **React**.

---

## Table of Contents

- [Overview](#overview)
- [What Makes This Different](#what-makes-this-different)
- [Architecture](#architecture)
- [Security Architecture — 16 Defense Layers](#security-architecture--16-defense-layers)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Environment Variables & `.env` File](#environment-variables--env-file)
- [Running the Project](#running-the-project)
- [AG-UI React Dashboard](#ag-ui-react-dashboard)
- [Docker Deployment](#docker-deployment)
- [Demo Scenarios](#demo-scenarios)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [LangChain Agent Details](#langchain-agent-details)
- [Troubleshooting](#troubleshooting)
- [Further Reading](#further-reading)
- [License](#license)

---

## Overview

HandshakeOS extends the [A2A Protocol](https://a2a-protocol.org/latest/specification/) with a **mandatory Proof-of-Authority governance handshake**. Every agent-to-agent request must pass through **16 security layers** before execution:

### Core Governance (10 Steps)
- ✅ **Verifiable Credential** — Agent Passport (W3C VC Data Model v2.0)
- ✅ **Human-backed delegation proof** — Chain of Command with hash-chain ledger
- ✅ **Privacy-preserving policy proof** — ZKP range proofs (amount ≤ limit without revealing amount)
- ✅ **Intent-risk scoring** — 6-signal behavioral rogue agent detection
- ✅ **Quorum-signed Trust Receipt** — PoA validation (2-of-3 / 3-of-5)
- ✅ **Authority intersection** — Effective Permission = Requester ∩ Target ∩ Delegation ∩ Policy ∩ Risk
- ✅ **Revocation enforcement** — Sub-second global revocation with fail-closed design
- ✅ **Circuit breaker** — Automatic agent quarantine on risk threshold breach
- ✅ **Trust Receipt ledger** — Append-only audit trail of all governance decisions
- ✅ **Segregation of duties** — Agents cannot self-approve

### Advanced Security (6 Modules)
- 🔒 **Security Audit Logger** — Tamper-evident hash-chained audit trail (14 categories, 5 severity levels)
- ⏱️ **API Rate Limiter** — Per-agent + per-IP sliding-window rate limiting with graduated penalties
- 🛡️ **Prompt Injection Shield** — 6-layer deep injection detection (classic, encoding, indirect, multi-language, semantic, token-level)
- 🔁 **Replay Attack Guard** — Nonce/timestamp/hash-based replay prevention
- 📊 **Behavioral Anomaly Detector** — Time-series anomaly detection with per-agent profiling
- 🍯 **Honeypot / Canary System** — Deception-based rogue agent trapping with canary agents, actions, and endpoints

This converts A2A from a communication protocol into a **governed trust fabric** for autonomous enterprise operations.

> 📖 **For detailed documentation of every security feature, see [FEATURES.md](FEATURES.md)**

---

## What Makes This Different

Most teams show agents talking to each other. **HandshakeOS shows agents refusing to trust each other unless authority is proven.**

| Aspect | Typical A2A | HandshakeOS |
|--------|-------------|-------------|
| **Identity** | None / API keys | W3C Verifiable Credentials |
| **Authorization** | None / static roles | Human-delegated authority with expiry |
| **Policy** | Hardcoded limits | Privacy-preserving ZKP proofs |
| **Trust** | Implicit | PoA validator quorum with Trust Receipts |
| **Rogue Detection** | None | 6-signal behavioral analysis + circuit breaker |
| **Revocation** | Manual / slow | Sub-millisecond global revocation |
| **Prompt Injection** | None | 6-layer multi-signal detection engine |
| **Replay Protection** | None | Nonce + timestamp + hash deduplication |
| **Audit Trail** | Application logs | Tamper-evident hash-chained security ledger |
| **Deception Defense** | None | Honeypot agents, canary actions, trap endpoints |

---

## Architecture

```
                        Human Admin Console
                                 |
                                 v
                     Delegation + Revocation Service
                                 |
                                 v
+----------------+        +--------------------+        +------------------+
| HR Agent       | -----> | AGL Sidecar/Gateway| -----> | Finance Agent    |
| (LangChain)    | A2A    | HandshakeOS Layer  | A2A    | (LangChain)      |
+----------------+        +--------------------+        +------------------+
        |                        |                              |
        v                        v                              v
  AG-UI Dashboard        PoA Validator Quorum          Trust Receipt Ledger
  (React + SSE)    Identity+Delegation+Policy+Risk

                  ┌─────────────────────────────────┐
                  │    6 Advanced Security Modules   │
                  ├─────────────────────────────────┤
                  │ Audit Logger (hash-chained)     │
                  │ Rate Limiter (per-agent + IP)   │
                  │ Prompt Injection Shield (6-layer)│
                  │ Replay Guard (nonce + hash)     │
                  │ Anomaly Detector (behavioral)   │
                  │ Honeypot / Canary (deception)   │
                  └─────────────────────────────────┘
```

### Governance Handshake Flow (16 Steps)

```
Request arrives at AGL Gateway
  │
  ├── S1. Rate Limit Check ────────── Per-agent + per-IP throttling
  ├── S2. Prompt Injection Scan ───── 6-layer injection detection
  ├── S3. Replay Guard ─────────────  Nonce + timestamp + hash check
  ├── S4. Honeypot Canary Check ───── Canary action/agent detection
  │
  ├──  1. AGL Extension Header ────── Verify governance extension present
  ├──  2. Extract Envelope ─────────  Parse governance envelope
  ├──  3. Revocation Check ─────────  Fast fail-closed denylist check
  ├──  4. Identity Verification ────  Verify Agent Passport VC (JWT)
  ├──  5. Delegation Chain ─────────  Verify human delegation chain
  ├──  6. Authority Intersection ───  Effective Permission calculation
  ├──  7. ZKP Policy Proof ─────────  Verify amount ≤ limit (privacy-preserving)
  ├──  8. Intent Risk Scoring ──────  6-signal behavioral analysis
  │       └── S5. Anomaly Detection   Time-series anomaly boost
  ├──  9. PoA Quorum ───────────────  Collect validator signatures
  ├── 10. Trust Receipt + Execute ──  Issue receipt, forward to agent
  │
  └── S6. Audit Log ────────────────  Hash-chained tamper-evident trail
```

---

## Security Architecture — 16 Defense Layers

HandshakeOS implements defense-in-depth with 16 security layers across 4 categories:

### 🛡️ Pre-Handshake Defenses (S1–S4)
| Layer | Module | Threat Mitigated |
|-------|--------|-----------------|
| S1 | Rate Limiter | DoS, brute-force |
| S2 | Prompt Injection Shield | Prompt injection, jailbreak, data exfiltration |
| S3 | Replay Guard | Replay attacks, stale envelopes |
| S4 | Honeypot Canary | Reconnaissance, unauthorized scanning |

### 🔐 Core Governance (Steps 1–10)
| Step | Check | Threat Mitigated |
|------|-------|-----------------|
| 1-2 | Envelope validation | Protocol compliance |
| 3 | Revocation check | Compromised agent access |
| 4 | Identity verification | Identity spoofing |
| 5 | Delegation chain | Unauthorized access |
| 6 | Authority intersection | Privilege escalation |
| 7 | ZKP policy proof | Policy circumvention |
| 8 | Intent risk scoring | Rogue agent behavior |
| 9 | PoA quorum | Single-point-of-failure trust |
| 10 | Trust Receipt | Unauthorized execution |

### 📊 In-Handshake Analysis (S5)
| Layer | Module | Threat Mitigated |
|-------|--------|-----------------|
| S5 | Anomaly Detector | Behavioral drift, insider threats |

### 📝 Post-Handshake (S6)
| Layer | Module | Threat Mitigated |
|-------|--------|-----------------|
| S6 | Audit Logger | Forensics, compliance, tampering |

> 📖 **See [FEATURES.md](FEATURES.md) for complete technical details on every feature.**

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.11+ | Tested with 3.12 |
| **Node.js** | 18+ | For the AG-UI React dashboard |
| **npm** | 9+ | Comes with Node.js |
| **Docker** *(optional)* | 20+ | For containerized deployment |

---

## Installation

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd "Pramaan A2A"
```

### 2. Create a Python Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

This installs:

| Package | Purpose |
|---------|---------|
| `fastapi` | Web framework for the API server |
| `uvicorn` | ASGI server |
| `a2a-sdk` | Google's Agent-to-Agent protocol SDK |
| `ag-ui-protocol` | AG-UI event protocol for agent↔user streaming |
| `sse-starlette` | Server-Sent Events support |
| `langchain` | LangChain agent framework |
| `langchain-core` | LangChain core primitives (tools, messages, prompts) |
| `langgraph` | LangGraph for agent orchestration |
| `pyjwt` | JWT signing for Verifiable Credentials |
| `httpx` | HTTP client |
| `pydantic` | Data validation |
| `streamlit` | Admin console UI |

### 4. Install the AG-UI React Dashboard

```bash
cd pramaan-a2a-ui
npm install
cd ..
```

---

## Environment Variables & `.env` File

### 🟢 No API Keys Required for Default Mode

The project runs **out of the box without any API keys**. Both LangChain agents use a deterministic `GenericFakeChatModel` (from `langchain_core`) that requires no LLM API calls. All governance logic is executed through LangChain tools directly.

### Optional: Using a Real LLM

To swap the deterministic model for a real LLM (e.g., OpenAI, Anthropic), create a `.env` file in the project root:

```bash
# .env — Optional, only needed if you want to use a real LLM

# ── OpenAI (if using ChatOpenAI) ──
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxx

# ── Anthropic (if using ChatAnthropic) ──
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxx

# ── Server Config (optional) ──
HOST=0.0.0.0
PORT=8200
```

Then update the agent files to load the real LLM:

```python
# In agents/hr_relocation_agent.py, replace _build_hr_llm() with:
from langchain_openai import ChatOpenAI
def _build_hr_llm():
    return ChatOpenAI(model="gpt-4o", temperature=0)
```

> **Important**: Add `.env` to your `.gitignore` to avoid committing secrets.

---

## Running the Project

### Quick Start (3 terminals)

#### Terminal 1 — Backend API Server

```bash
source .venv/bin/activate
python main.py
```

The server starts at **http://localhost:8200**

You should see:
```
🤝 HandshakeOS AGL Gateway started
   → HR Agent:      did:gcc:agent:hr-relocation-07
   → Finance Agent: did:gcc:agent:finance-disbursement-02
   → Policy:        policy-relocation-autopay-v3 ($10,000 limit)
   → Quorum:        2-of-3 (low risk) / 3-of-5 (high risk)
   → Security:      6 modules active (audit, rate-limit, prompt-shield, replay-guard, anomaly, honeypot)
```

#### Terminal 2 — AG-UI React Dashboard

```bash
cd pramaan-a2a-ui
npm run dev
```

Dashboard opens at **http://localhost:3001**

#### Terminal 3 — Admin Console *(optional)*

```bash
source .venv/bin/activate
streamlit run ui/admin_console.py
```

Streamlit dashboard at **http://localhost:8501**

### Run Smoke Tests

```bash
python test_smoke.py
```

Expected output:
```
✅ All modules imported successfully (including 6 security modules)!
✅ VC issuance + verify: ok=True
✅ ZKP range proof: valid=True, claim=amount_is_under_limit
✅ ZKP over-limit: valid=False (expected False)
✅ Intent Sentinel: 25 requests, 25 threshold hugging
✅ Delegation ledger: valid=True

── Security Module Tests ──
✅ Audit Logger: 2 events, chain_valid=True
✅ Rate Limiter: allowed=True, penalty=warn, remaining=1
✅ Prompt Injection Shield (injection): detected=True
✅ Prompt Injection Shield (legit): detected=False
✅ Replay Guard: first=True, replay_blocked=True
✅ Anomaly Detector: anomaly detected
✅ Honeypot: canary_agent_triggered=True, canary_action_triggered=True

✅ All smoke tests passed (including 6 security modules)!
```

---

## AG-UI React Dashboard

The AG-UI dashboard at `ag-ui-dashboard/` provides a real-time visualization of the governance handshake using the **AG-UI Protocol** (Server-Sent Events).

### Features

| Feature | Description |
|---------|-------------|
| **Scenario Selector** | 5 scenarios: Valid Handshake, Privilege Escalation, Rogue Agent, Global Revocation, Live Handshake |
| **Agent Topology** | Visual diagram of HR Agent → AGL Gateway → Finance Agent |
| **Governance Pipeline** | Step-by-step visualization of all governance checks |
| **Event Stream** | Real-time AG-UI events (RUN_STARTED, STEP_STARTED, CUSTOM, STATE_SNAPSHOT, etc.) |
| **Agent Response** | Streamed markdown response from the governance handshake |
| **State Viewer** | Outcome cards (APPROVED/REJECTED/QUARANTINED/REVOKED) |
| **Security Dashboard** | Live agent status, trust receipt counts, revocation metrics |

### Build for Production

```bash
cd pramaan-a2a-ui
npm run build
```

---

## Docker Deployment

### Using Docker Compose

```bash
docker-compose up --build
```

This starts:
- **Backend API** at `http://localhost:8200`
- **Admin Console** at `http://localhost:8501`

### Using Docker Only (Backend)

```bash
docker build -t pramaan-a2a .
docker run -p 8200:8200 pramaan-a2a
```

---

## Demo Scenarios

Access demos via browser or `curl` once the server is running:

| # | Demo | URL | What Happens |
|---|------|-----|-------------|
| 1 | ✅ Valid Handshake | `GET /demo/valid-handshake` | HR Agent requests $8,000 relocation payment. All governance checks pass. Trust Receipt issued. |
| 2 | 🛡️ Privilege Escalation | `GET /demo/privilege-escalation` | HR Agent attempts $50,000 without authority. Authority intersection + ZKP policy block it. |
| 3 | 🚨 Rogue Agent | `GET /demo/rogue-agent` | 25 rapid-fire requests of $9,950 (threshold hugging). Circuit breaker activates. Agent quarantined. |
| 4 | 🚫 Global Revocation | `GET /demo/global-revocation` | Human admin revokes agent. Enforced in <1ms. All future requests blocked. |
| 5 | 🛡️ Prompt Injection | `GET /demo/prompt-injection` | Tests 6 inputs against the 6-layer Prompt Injection Shield. Injections blocked, legit passes. |
| 6 | 🔁 Replay Attack | `GET /demo/replay-attack` | Submits governance envelope, then attempts exact replay. Replay detected and blocked. |
| 7 | 🍯 Honeypot Canary | `GET /demo/honeypot-canary` | Rogue agent accesses canary agent card, requests canary action, hits trap endpoint. All detected. |

### Via curl

```bash
# Demo 1–4: Core Governance
curl http://localhost:8200/demo/valid-handshake | python -m json.tool
curl http://localhost:8200/demo/privilege-escalation | python -m json.tool
curl http://localhost:8200/demo/rogue-agent | python -m json.tool
curl http://localhost:8200/demo/global-revocation | python -m json.tool

# Demo 5–7: Advanced Security
curl http://localhost:8200/demo/prompt-injection | python -m json.tool
curl http://localhost:8200/demo/replay-attack | python -m json.tool
curl http://localhost:8200/demo/honeypot-canary | python -m json.tool

# Security Dashboard
curl http://localhost:8200/security/dashboard | python -m json.tool
```

### Via AG-UI Dashboard

Open **http://localhost:3001**, select a scenario, and click **▶ Run Scenario** to see the governance handshake stream in real-time.

---

## API Reference

### A2A Protocol
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/a2a/message:send` | Send governed A2A message with AGL envelope |
| `GET` | `/a2a/agent-card/{agent_id}` | Get agent card with AGL extension |
| `GET` | `/a2a/health` | Health check with security module status |

### AG-UI Protocol
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/ag-ui/run` | Stream AG-UI events (SSE) for a governance scenario |
| `GET` | `/ag-ui/status` | System status for the dashboard |
| `GET` | `/ag-ui/metrics` | Security metrics (risk, receipts, revocations) |

### Demo Scenarios
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/demo/valid-handshake` | Demo 1: Valid $8k handshake |
| `GET` | `/demo/privilege-escalation` | Demo 2: $50k escalation blocked |
| `GET` | `/demo/rogue-agent` | Demo 3: Circuit breaker triggered |
| `GET` | `/demo/global-revocation` | Demo 4: Sub-second revocation |
| `GET` | `/demo/prompt-injection` | Demo 5: 6-layer prompt injection detection |
| `GET` | `/demo/replay-attack` | Demo 6: Replay attack prevention |
| `GET` | `/demo/honeypot-canary` | Demo 7: Honeypot / canary detection |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/admin/approve` | Approve high-value request |
| `POST` | `/admin/revoke/{agent_did}` | Globally revoke agent |
| `GET` | `/admin/status` | System status dashboard |
| `GET` | `/admin/risk-features/{agent_did}` | Risk features for agent |

### Security
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/security/dashboard` | Comprehensive security dashboard (all modules) |
| `GET` | `/security/audit-log` | Query security audit log with filters |
| `GET` | `/security/threats` | Real-time threat summary |
| `GET` | `/security/agent-profile/{agent_did}` | Security profile for an agent |
| `GET` | `/security/honeypot-alerts` | Honeypot canary alerts |

---

## Project Structure

```
Pramaan A2A/
├── main.py                          # FastAPI application entry point
├── agui_endpoint.py                 # AG-UI Protocol SSE streaming endpoint
├── requirements.txt                 # Python dependencies
├── Dockerfile                       # Docker container
├── docker-compose.yml               # Multi-container setup
├── test_smoke.py                    # Smoke tests (all modules incl. security)
├── FEATURES.md                      # Detailed feature documentation
├── DEMO_SCRIPT.md                   # Demo presentation script
│
├── agents/                          # 🤖 LangChain Agents
│   ├── hr_relocation_agent.py       #   HR Agent — 4 LangChain tools
│   └── finance_disbursement_agent.py#   Finance Agent — 3 LangChain tools
│
├── agl/                             # 🏛️ Agent Governance Layer
│   ├── gateway.py                   #   AGL Gateway / Sidecar (16-step handshake)
│   ├── governance_envelope.py       #   Governance envelope builder
│   ├── poa_quorum.py                #   Proof-of-Authority quorum
│   └── trust_receipt.py             #   Trust Receipt model
│
├── identity/                        # 🪪 Identity & Credentials
│   ├── vc_issuer.py                 #   Verifiable Credential issuer
│   └── vc_verifier.py               #   VC verification (JWT)
│
├── ledger/                          # 📜 Delegation Ledger
│   ├── schema.sql                   #   SQLite schema
│   └── delegation_ledger.py         #   Delegation + Trust Receipt ledger
│
├── policy/                          # 🔒 Policy Engine
│   ├── policy_engine.py             #   Policy evaluation engine
│   ├── zkp_mock_verifier.py         #   Mock ZKP range proof verifier
│   └── under_limit.circom           #   Circom circuit (reference)
│
├── risk/                            # 🎯 Risk Engine
│   ├── intent_sentinel.py           #   Rogue agent detection (6 signals)
│   └── circuit_breaker.py           #   Circuit breaker + quarantine
│
├── revocation/                      # 🚫 Revocation Service
│   ├── revocation_bus.py            #   In-memory pub/sub bus
│   └── revocation_cache.py          #   Local denylist cache (fail-closed)
│
├── security/                        # 🛡️ Advanced Security Modules
│   ├── __init__.py                  #   Module exports
│   ├── audit_logger.py              #   Tamper-evident hash-chained audit trail
│   ├── rate_limiter.py              #   Per-agent + per-IP rate limiting
│   ├── prompt_injection_shield.py   #   6-layer prompt injection detection
│   ├── replay_guard.py              #   Nonce/timestamp replay prevention
│   ├── anomaly_detector.py          #   Behavioral anomaly detection
│   └── honeypot.py                  #   Honeypot / canary token system
│
├── ui/                              # 📊 Admin Console
│   └── admin_console.py             #   Streamlit dashboard
│
└── ag-ui-dashboard/                 # ⚛️ AG-UI React Dashboard
    ├── package.json
    ├── vite.config.ts
    ├── index.html
    └── src/
        ├── App.tsx                  #   Main application
        ├── agui-client.ts           #   AG-UI SSE client
        └── components/
            ├── AgentTopology.tsx     #   Agent interaction diagram
            ├── GovernancePipeline.tsx#   Step-by-step pipeline view
            ├── EventStream.tsx      #   Real-time event log
            ├── MessagePanel.tsx     #   Agent response renderer
            ├── StateViewer.tsx      #   Outcome cards
            └── SecurityDashboard.tsx #   Security metrics panel
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Agent Framework** | LangChain + LangGraph (tools, prompts, agents) |
| **Agent Communication** | A2A SDK (Google's Agent-to-Agent protocol) |
| **Agent↔User Streaming** | AG-UI Protocol (SSE event stream) |
| **Backend** | Python FastAPI + Uvicorn |
| **Frontend** | React 19 + TypeScript + Vite |
| **Admin UI** | Streamlit |
| **Identity (VC)** | Signed JWT (W3C VC Data Model v2.0 compatible) |
| **Ledger** | SQLite hash-chain (append-only) |
| **PoA Validators** | Python validators with configurable quorum |
| **ZKP (Policy)** | Mock HMAC proof (Circom circuit reference) |
| **Revocation Bus** | In-memory pub/sub (production: Redis/NATS/Kafka) |
| **Risk Engine** | 6-signal behavioral analysis + circuit breaker |
| **Security Audit** | Hash-chained tamper-evident event trail |
| **Rate Limiting** | Sliding-window with graduated penalties |
| **Injection Defense** | 6-layer multi-signal detection engine |
| **Replay Defense** | Nonce + timestamp + hash deduplication |
| **Anomaly Detection** | Statistical behavioral profiling |
| **Deception Defense** | Honeypot agents + canary tokens |
| **Deployment** | Docker Compose |

---

## LangChain Agent Details

Both agents are built using the **LangChain framework** with `@tool` decorated functions, `ChatPromptTemplate` system prompts, and `GenericFakeChatModel` for deterministic execution.

### HR Relocation Agent

| Property | Value |
|----------|-------|
| **DID** | `did:gcc:agent:hr-relocation-07` |
| **Owner** | `did:gcc:employee:global-mobility-director` |
| **Framework** | LangChain |
| **LLM** | `GenericFakeChatModel` (swap for `ChatOpenAI` etc.) |

**LangChain Tools:**
| Tool | Description |
|------|-------------|
| `create_relocation_case` | Creates a relocation case with amount and reference |
| `validate_relocation_amount` | Validates amount against $10,000 policy limit |
| `check_agent_authority` | Checks allowed/forbidden action lists |
| `prepare_governance_envelope_data` | Prepares AGL governance envelope metadata |

### Finance Disbursement Agent

| Property | Value |
|----------|-------|
| **DID** | `did:gcc:agent:finance-disbursement-02` |
| **Framework** | LangChain |
| **LLM** | `GenericFakeChatModel` (swap for `ChatOpenAI` etc.) |

**LangChain Tools:**
| Tool | Description |
|------|-------------|
| `verify_trust_receipt` | Validates Trust Receipt is APPROVED and unused |
| `execute_payment` | Executes payment with one-time-use receipt enforcement |
| `check_duplicate_receipt` | Replay protection for Trust Receipts |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: a2a` | Run `pip install -r requirements.txt` in your venv |
| `ModuleNotFoundError: langchain` | Run `pip install langchain langchain-core langgraph` |
| AG-UI dashboard shows connection error | Make sure the backend is running on port 8200 first |
| `npm install` fails in `ag-ui-dashboard/` | Ensure Node.js 18+ is installed (`node --version`) |
| Port 8200 already in use | Kill the existing process: `lsof -ti:8200 \| xargs kill` |
| Port 3001 already in use | Kill the existing process or change port in `vite.config.ts` |
| SQLite lock error | Delete `handshakeos.db` and restart the server |
| Docker build fails | Ensure Docker daemon is running and you have internet access |

---

## Further Reading

- **[FEATURES.md](FEATURES.md)** — Detailed documentation of all 16 security features with technical deep-dives
- **[DEMO_SCRIPT.md](DEMO_SCRIPT.md)** — Step-by-step demo presentation script with talking points

---

## License

MIT
