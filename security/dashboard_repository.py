import sqlite3
import uuid
import os
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
from threading import Lock

class DashboardRepository:
    def __init__(self, db_path: str = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "handshakeos.db")
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._write_lock = Lock()

    def initialize(self):
        if os.environ.get("VERCEL"):
            self.db_path = "/tmp/demo.db"
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        
        with self._write_lock:
            self._conn.execute('''
                CREATE TABLE IF NOT EXISTS dashboard_agents (
                    agent_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    scan_interval_minutes INTEGER NOT NULL,
                    last_scan_time TIMESTAMP,
                    next_scan_time TIMESTAMP,
                    last_score REAL,
                    agent_type TEXT DEFAULT 'a2a',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            self._conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.initialize()
        return self._conn

    def add_agent(self, name: str, url: str, scan_interval_minutes: int, agent_type: str = "a2a") -> str:
        conn = self._get_conn()
        agent_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        
        # Check if already exists
        r = conn.execute("SELECT agent_id FROM dashboard_agents WHERE url = ?", (url,)).fetchone()
        if r:
            return r["agent_id"]

        with self._write_lock:
            conn.execute(
                "INSERT INTO dashboard_agents (agent_id, name, url, scan_interval_minutes, agent_type, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (agent_id, name, url, scan_interval_minutes, agent_type, now.isoformat())
            )
            conn.commit()
        return agent_id

    def update_agent_interval(self, agent_id: str, scan_interval_minutes: int):
        conn = self._get_conn()
        now = datetime.now(timezone.utc)
        next_scan = now + timedelta(minutes=scan_interval_minutes) if scan_interval_minutes > 0 else None
        
        with self._write_lock:
            conn.execute(
                "UPDATE dashboard_agents SET scan_interval_minutes = ?, next_scan_time = ? WHERE agent_id = ?",
                (scan_interval_minutes, next_scan.isoformat() if next_scan else None, agent_id)
            )
            conn.commit()

    def update_agent_scan(self, agent_id: str, last_score: float):
        conn = self._get_conn()
        r = conn.execute("SELECT scan_interval_minutes FROM dashboard_agents WHERE agent_id = ?", (agent_id,)).fetchone()
        if not r:
            return
            
        interval = r["scan_interval_minutes"]
        now = datetime.now(timezone.utc)
        next_scan = now + timedelta(minutes=interval) if interval > 0 else None
        
        with self._write_lock:
            conn.execute(
                "UPDATE dashboard_agents SET last_score = ?, last_scan_time = ?, next_scan_time = ? WHERE agent_id = ?",
                (last_score, now.isoformat(), next_scan.isoformat() if next_scan else None, agent_id)
            )
            conn.commit()

    def remove_agent(self, agent_id: str):
        conn = self._get_conn()
        with self._write_lock:
            conn.execute("DELETE FROM dashboard_agents WHERE agent_id = ?", (agent_id,))
            conn.commit()

    def get_all_agents(self) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM dashboard_agents ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def get_agents_due_for_scan(self) -> List[Dict]:
        conn = self._get_conn()
        now_str = datetime.now(timezone.utc).isoformat()
        
        # get agents where next_scan_time is not null and <= now
        rows = conn.execute(
            "SELECT * FROM dashboard_agents WHERE next_scan_time IS NOT NULL AND next_scan_time <= ?",
            (now_str,)
        ).fetchall()
        
        # Also return agents that have NEVER been scanned but have an interval > 0
        never_scanned = conn.execute(
            "SELECT * FROM dashboard_agents WHERE last_scan_time IS NULL AND scan_interval_minutes > 0"
        ).fetchall()
        
        # return combined (ensure unique by agent_id)
        agents = {r["agent_id"]: dict(r) for r in rows}
        for r in never_scanned:
            agents[r["agent_id"]] = dict(r)
            
        return list(agents.values())

dashboard_repository = DashboardRepository()
