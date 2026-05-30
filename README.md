README.md


# Pramaan A2A — HandshakeOS

**A Proof-of-Authority Governance Extension for Agent-to-Agent Trust**

> A2A enables agents to talk. HandshakeOS decides whether they should trust and obey each other.

> **Security in the Agentic Future** — AI agents are powerful but they're also new attack surfaces. HandshakeOS provides monitoring frameworks, defense mechanisms, and trust architectures that keep agentic systems safe from prompt injection, identity spoofing, unauthorized access, and adversarial misuse.

Built with **LangChain**, **A2A SDK**, **AG-UI Protocol**, **FastAPI**, and **React**.

---

## Table of Contents

- [Overview](#overview)
- [What Makes This Different](#what-makes-this-different)
- [Architecture](#architecture)
- [Security Architecture : 16 Defense Layers](#security-architecture--16-defense-layers)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [License](#license)

---

## Overview

HandshakeOS extends the [A2A Protocol](https://a2a-protocol.org/latest/specification/) with a **mandatory Proof-of-Authority governance handshake**. Every agent-to-agent request must pass through **16 security layers** before execution:

### Core Governance (10 Steps)
-  **Verifiable Credential** : Agent Passport (W3C VC Data Model v2.0)
-  **Human-backed delegation proof** : Chain of Command with hash-chain ledger
-  **Privacy-preserving policy proof** : ZKP range proofs (amount ≤ limit without revealing amount)
-  **Intent-risk scoring** : 6-signal behavioral rogue agent detection
-  **Quorum-signed Trust Receipt** : PoA validation (2-of-3 / 3-of-5)
-  **Authority intersection** : Effective Permission = Requester ∩ Target ∩ Delegation ∩ Policy ∩ Risk
-  **Revocation enforcement** : Sub-second global revocation with fail-closed design
-  **Circuit breaker** : Automatic agent quarantine on risk threshold breach
-  **Trust Receipt ledger** : Append-only audit trail of all governance decisions
-  **Segregation of duties** : Agents cannot self-approve

### Advanced Security (6 Modules)
-  **Security Audit Logger** : Tamper-evident hash-chained audit trail (14 categories, 5 severity levels)
-  **API Rate Limiter** : Per-agent + per-IP sliding-window rate limiting with graduated penalties
-  **Prompt Injection Shield** : 6-layer deep injection detection (classic, encoding, indirect, multi-language, semantic, token-level)
-  **Replay Attack Guard** : Nonce/timestamp/hash-based replay prevention
-  **Behavioral Anomaly Detector** : Time-series anomaly detection with per-agent profiling
-  **Honeypot / Canary System** : Deception-based rogue agent trapping with canary agents, actions, and endpoints

This converts A2A from a communication protocol into a **governed trust fabric** for autonomous enterprise operations.

> **For detailed documentation of every security feature, see [FEATURES.md](FEATURES.md)**

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

## Security Architecture : 16 Defense Layers

HandshakeOS implements defense-in-depth with 16 security layers across 4 categories:

### ️ Pre-Handshake Defenses (S1–S4)
| Layer | Module | Threat Mitigated |
|-------|--------|-----------------|
| S1 | Rate Limiter | DoS, brute-force |
| S2 | Prompt Injection Shield | Prompt injection, jailbreak, data exfiltration |
| S3 | Replay Guard | Replay attacks, stale envelopes |
| S4 | Honeypot Canary | Reconnaissance, unauthorized scanning |

###  Core Governance (Steps 1–10)
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

###  In-Handshake Analysis (S5)
| Layer | Module | Threat Mitigated |
|-------|--------|-----------------|
| S5 | Anomaly Detector | Behavioral drift, insider threats |

###  Post-Handshake (S6)
| Layer | Module | Threat Mitigated |
|-------|--------|-----------------|
| S6 | Audit Logger | Forensics, compliance, tampering |

>  **See [FEATURES.md](FEATURES.md) for complete technical details on every feature.**

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
git clone https://github.com/IntelegixLabs/Pramaan_A2A
cd "Pramaan_A2A"
```

### 2. Create a Python Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows
```

### 3. Install Python Dependencies and run the backend Layer

```bash
pip install -r requirements.txt
python main.py
```



### 4. Install the AG-UI React Dashboard and run it in a separate terminal

```bash
git clone https://github.com/IntelegixLabs/Pramaan_A2A_UI
cd Pramaan_A2A_UI
npm install
npm run dev
```

---


### Run Smoke Tests

```bash
python test_smoke.py
```


## License

MIT
