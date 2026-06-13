from observability.tracer import langfuse_context
from langfuse import Langfuse
from langfuse.langchain import CallbackHandler
import os

os.environ["LANGFUSE_SECRET_KEY"] = "sk-lf-test"
os.environ["LANGFUSE_PUBLIC_KEY"] = "pk-lf-test"

handler = CallbackHandler()

with langfuse_context(session_id="test"):
    from langchain_core.messages import HumanMessage
    from langchain_core.prompts import PromptTemplate
    from langchain_core.runnables import RunnableLambda
    
    chain = RunnableLambda(lambda x: x)
    chain.invoke("hello", config={"callbacks": [handler]})
    
    print("last_trace_id:", getattr(handler, "last_trace_id", None))
    try:
        url = handler.langfuse.get_trace_url()
        print("handler.langfuse.get_trace_url():", url)
    except Exception as e:
        print(e)
