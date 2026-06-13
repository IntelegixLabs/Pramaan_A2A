import json
import logging
from typing import Any, Callable

from langchain_core.tools import tool, Tool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, SystemMessage

from llm_factory import build_llm
from security.agent_manager import agent_manager

logger = logging.getLogger(__name__)

def create_dynamic_tool(name: str, description: str, code_str: str) -> Tool:
    """Safely (for demo purposes) evaluate code_str to create a python function, and wrap it in a Langchain Tool."""
    local_env = {}
    try:
        # We expect the code_str to define a function with the same name as the tool
        exec(code_str, globals(), local_env)
        func = local_env.get(name)
        if not func or not callable(func):
            # Fallback if they didn't name it exactly right, just grab the first callable
            callables = [v for k, v in local_env.items() if callable(v)]
            if callables:
                func = callables[0]
            else:
                raise ValueError(f"No callable function found in code for tool {name}")
        
        # Wrap it in a Langchain Tool
        return Tool(
            name=name,
            description=description,
            func=func
        )
    except Exception as e:
        logger.error(f"Failed to compile custom tool {name}: {e}")
        # Return a dummy tool that just returns the error
        return Tool(
            name=name,
            description=description,
            func=lambda *args, **kwargs: f"Error executing tool {name}: {e}"
        )

class CustomAgentRunner:
    """Loads a custom agent from the DB and runs it."""
    def __init__(self, agent_id: str):
        self.agent_data = agent_manager.get_agent(agent_id)
        if not self.agent_data:
            raise ValueError(f"Agent {agent_id} not found")
            
        self.llm = build_llm()
        self.tools = []
        for t in self.agent_data.get("tools", []):
            if t.get("code"):
                self.tools.append(create_dynamic_tool(t["name"], t["description"], t["code"]))
                
        # In LangGraph, we bind tools directly to the react agent
        self.agent_executor = create_react_agent(self.llm, self.tools)

    def invoke(self, message: str) -> str:
        """Run the agent with a user message."""
        try:
            messages = [
                SystemMessage(content=self.agent_data.get("system_prompt", "You are a helpful assistant.")),
                HumanMessage(content=message)
            ]
            result = self.agent_executor.invoke({"messages": messages})
            messages = result.get("messages", [])
            if messages:
                return messages[-1].content
            return "No response."
        except Exception as e:
            return f"Agent execution failed: {e}"
