import sqlite3
import json
import uuid
import os

if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/handshakeos.db"
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), "..", "handshakeos.db")

class AgentManager:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS custom_agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    system_prompt TEXT,
                    policies TEXT,
                    max_budget INTEGER DEFAULT 10
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS custom_tools (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT,
                    name TEXT NOT NULL,
                    description TEXT,
                    code TEXT,
                    FOREIGN KEY(agent_id) REFERENCES custom_agents(id) ON DELETE CASCADE
                )
            ''')
            conn.commit()

    def get_all_agents(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM custom_agents')
            agents = [dict(row) for row in cursor.fetchall()]
            for agent in agents:
                agent['policies'] = json.loads(agent['policies']) if agent['policies'] else {}
                cursor.execute('SELECT id, name, description, code FROM custom_tools WHERE agent_id = ?', (agent['id'],))
                agent['tools'] = [dict(row) for row in cursor.fetchall()]
            return agents

    def get_agent(self, agent_id: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM custom_agents WHERE id = ?', (agent_id,))
            row = cursor.fetchone()
            if not row:
                return None
            agent = dict(row)
            agent['policies'] = json.loads(agent['policies']) if agent['policies'] else {}
            cursor.execute('SELECT id, name, description, code FROM custom_tools WHERE agent_id = ?', (agent_id,))
            agent['tools'] = [dict(row) for row in cursor.fetchall()]
            return agent

    def create_agent(self, agent_data: dict):
        agent_id = str(uuid.uuid4())
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO custom_agents (id, name, description, system_prompt, policies, max_budget)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                agent_id,
                agent_data.get('name', 'Custom Agent'),
                agent_data.get('description', ''),
                agent_data.get('system_prompt', 'You are a helpful assistant.'),
                json.dumps(agent_data.get('policies', {})),
                agent_data.get('max_budget', 10)
            ))
            
            for tool in agent_data.get('tools', []):
                tool_id = str(uuid.uuid4())
                cursor.execute('''
                    INSERT INTO custom_tools (id, agent_id, name, description, code)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    tool_id,
                    agent_id,
                    tool.get('name'),
                    tool.get('description'),
                    tool.get('code')
                ))
            conn.commit()
        return self.get_agent(agent_id)

    def update_agent(self, agent_id: str, agent_data: dict):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE custom_agents 
                SET name = ?, description = ?, system_prompt = ?, policies = ?, max_budget = ?
                WHERE id = ?
            ''', (
                agent_data.get('name'),
                agent_data.get('description'),
                agent_data.get('system_prompt'),
                json.dumps(agent_data.get('policies', {})),
                agent_data.get('max_budget', 10),
                agent_id
            ))
            
            # Recreate tools for simplicity
            cursor.execute('DELETE FROM custom_tools WHERE agent_id = ?', (agent_id,))
            for tool in agent_data.get('tools', []):
                tool_id = str(uuid.uuid4())
                cursor.execute('''
                    INSERT INTO custom_tools (id, agent_id, name, description, code)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    tool_id,
                    agent_id,
                    tool.get('name'),
                    tool.get('description'),
                    tool.get('code')
                ))
            conn.commit()
        return self.get_agent(agent_id)

    def delete_agent(self, agent_id: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM custom_tools WHERE agent_id = ?', (agent_id,))
            cursor.execute('DELETE FROM custom_agents WHERE id = ?', (agent_id,))
            conn.commit()
        return True

agent_manager = AgentManager()
