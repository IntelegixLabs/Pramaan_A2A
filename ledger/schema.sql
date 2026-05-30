CREATE TABLE IF NOT EXISTS delegation_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    human_leader_id TEXT NOT NULL,
    agent_did TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    valid_from TIMESTAMP NOT NULL,
    valid_until TIMESTAMP NOT NULL,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL,
    signed_by TEXT NOT NULL,
    signature TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS trust_receipts (
    receipt_id TEXT PRIMARY KEY,
    handshake_id TEXT NOT NULL,
    requester_agent_did TEXT NOT NULL,
    target_agent_did TEXT NOT NULL,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    poa_quorum TEXT NOT NULL,
    validator_signatures TEXT NOT NULL,
    risk_score REAL,
    ledger_root TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS revocation_events (
    revocation_id TEXT PRIMARY KEY,
    agent_did TEXT NOT NULL,
    revoked_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    effective_at TIMESTAMP NOT NULL,
    global_sequence_number INTEGER NOT NULL,
    signature TEXT NOT NULL
);

