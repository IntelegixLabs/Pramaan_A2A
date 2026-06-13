from fastapi import APIRouter, HTTPException
from typing import List, Dict

from security.pii_redactor import pii_redactor
from security.goal_checker import goal_checker
from security.output_validator import output_validator
from security.sandbox import sandbox
from security.authorization import authorization_engine
from security.human_review import human_review_queue
from security.agent_manager import agent_manager
from fastapi import UploadFile, File, Form
from security.document_scanner import scan_document
from security.rag_manager import rag_manager
from security.pii_redactor import pii_redactor

router = APIRouter(prefix="/admin", tags=["admin", "security"])

# --- PII Redactor ---
@router.get("/pii")
async def get_pii_rules():
    return pii_redactor.get_patterns()

@router.post("/pii")
async def set_pii_rules(patterns: dict):
    pii_redactor.set_patterns(patterns)
    return {"status": "success"}

# --- Goal Checker ---
@router.get("/goals")
async def get_goals():
    return goal_checker.get_rules()

@router.post("/goals")
async def set_goals(rules: dict):
    goal_checker.set_rules(rules)
    return {"status": "success"}

# --- Output Validator ---
@router.get("/output-validator")
async def get_output_validator():
    return {"blocklist": output_validator.get_blocklist()}

@router.post("/output-validator")
async def set_output_validator(body: dict):
    if "blocklist" in body:
        output_validator.set_blocklist(body["blocklist"])
    return {"status": "success"}

# --- Sandbox ---
@router.get("/sandbox")
async def get_sandbox():
    return sandbox.get_config()

@router.post("/sandbox")
async def set_sandbox(config: dict):
    sandbox.set_config(
        blocked=config.get("blocked_tools", sandbox.blocked_tools),
        max_calls=config.get("max_tool_calls", sandbox.max_tool_calls)
    )
    return {"status": "success"}

# --- Authorization (OPA Rego) ---
@router.get("/authorization")
async def get_rego_policy():
    return {"rego": authorization_engine.get_rego()}

@router.post("/authorization")
async def set_rego_policy(body: dict):
    if "rego" in body:
        authorization_engine.set_rego(body["rego"])
    return {"status": "success"}

# --- Human Review ---
@router.get("/reviews")
async def get_pending_reviews():
    return human_review_queue.get_pending_reviews()

@router.post("/reviews/{review_id}/approve")
async def approve_review(review_id: str):
    if human_review_queue.approve(review_id):
        return {"status": "approved"}
    raise HTTPException(status_code=404, detail="Review not found or not pending")

@router.post("/reviews/{review_id}/reject")
async def reject_review(review_id: str):
    if human_review_queue.reject(review_id):
        return {"status": "rejected"}
    raise HTTPException(status_code=404, detail="Review not found or not pending")

# --- Custom Agents ---
@router.get("/agents")
async def get_custom_agents():
    return agent_manager.get_all_agents()

@router.delete("/agents/{agent_id}")
async def delete_custom_agent(agent_id: str):
    if agent_manager.delete_agent(agent_id):
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Agent not found")

# --- RAG Knowledge Base ---
@router.post("/rag/upload")
async def upload_document(file: UploadFile = File(...), skip_security: bool = Form(False), mask_pii: bool = Form(False)):
    content = await file.read()
    
    # 1. Extract text for scanning
    try:
        text_preview = rag_manager.extract_text(content, file.filename)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    # 1.5 Mask PII if enabled
    if mask_pii:
        redaction_result = pii_redactor.redact(text_preview)
        text_preview = redaction_result.text
        
    # 2. Agentic Security Scan
    scan_result = {"is_safe": True, "reason": "Security scan bypassed."}
    if not skip_security:
        scan_result = scan_document(file.filename, text_preview)
        if not scan_result.get("is_safe", False):
            raise HTTPException(status_code=403, detail=f"Agentic Security Rejected Document: {scan_result.get('reason')}")
        
    # 3. Ingest into Chroma
    try:
        doc_info = rag_manager.ingest_document(file.filename, raw_text=text_preview)
        return {"status": "success", "document": doc_info, "scan": scan_result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest document: {str(e)}")

@router.get("/rag/documents")
async def get_documents():
    return rag_manager.get_documents()

@router.get("/rag/documents/{doc_id}")
async def get_document_content(doc_id: str):
    text = rag_manager.get_document_text(doc_id)
    if not text or text == "Text not found.":
        raise HTTPException(status_code=404, detail="Document text not found")
    return {"id": doc_id, "text": text}

@router.delete("/rag/documents/{doc_id}")
async def delete_document(doc_id: str):
    if rag_manager.delete_document(doc_id):
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Document not found")

@router.get("/agents/{agent_id}")
async def get_custom_agent(agent_id: str):
    agent = agent_manager.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent

@router.post("/agents")
async def create_custom_agent(agent_data: dict):
    agent = agent_manager.create_agent(agent_data)
    return agent

@router.put("/agents/{agent_id}")
async def update_custom_agent(agent_id: str, agent_data: dict):
    agent = agent_manager.update_agent(agent_id, agent_data)
    return agent

@router.delete("/agents/{agent_id}")
async def delete_custom_agent(agent_id: str):
    agent_manager.delete_agent(agent_id)
    return {"status": "success"}

# --- Security Scans ---
from security.scan_repository import scan_repository

@router.get("/scans")
async def get_security_scans():
    return {"scans": scan_repository.get_all_scans()}

@router.delete("/scans/{scan_id}")
async def delete_security_scan(scan_id: str):
    if scan_repository.delete_scan(scan_id):
        return {"status": "success"}
    raise HTTPException(status_code=404, detail="Scan not found")

@router.post("/scans/compare")
async def compare_scans(body: dict):
    scan1_id = body.get("scan1_id")
    scan2_id = body.get("scan2_id")
    if not scan1_id or not scan2_id:
        raise HTTPException(status_code=400, detail="Missing scan IDs")
        
    scan1 = scan_repository.get_scan(scan1_id)
    scan2 = scan_repository.get_scan(scan2_id)
    
    if not scan1 or not scan2:
        raise HTTPException(status_code=404, detail="One or both scans not found")
        
    # Generate delta: new vulnerabilities vs resolved ones
    s1_findings = {f["title"]: f for f in scan1["findings"]}
    s2_findings = {f["title"]: f for f in scan2["findings"]}
    
    resolved = [f for title, f in s1_findings.items() if title not in s2_findings]
    new_vulns = [f for title, f in s2_findings.items() if title not in s1_findings]
    persistent = [f for title, f in s2_findings.items() if title in s1_findings]
    
    return {
        "scan1": scan1,
        "scan2": scan2,
        "comparison": {
            "resolved": resolved,
            "new_vulnerabilities": new_vulns,
            "persistent": persistent,
            "score_delta": scan2["risk_score"] - scan1["risk_score"]
        }
    }

# --- Dashboard Agents (Tracking) ---
from security.dashboard_repository import dashboard_repository

@router.get("/dashboard-agents")
async def get_dashboard_agents():
    return dashboard_repository.get_all_agents()

@router.post("/dashboard-agents")
async def add_or_update_dashboard_agent(body: dict):
    agent_id = body.get("agent_id")
    name = body.get("name")
    url = body.get("url")
    interval = body.get("scan_interval_minutes", 0)
    agent_type = body.get("agent_type", "a2a")
    
    if agent_id:
        dashboard_repository.update_agent_interval(agent_id, interval)
        return {"status": "success", "agent_id": agent_id}
    else:
        if not name or not url:
            raise HTTPException(status_code=400, detail="Missing name or url")
        new_id = dashboard_repository.add_agent(name, url, interval, agent_type)
        return {"status": "success", "agent_id": new_id}

@router.delete("/dashboard-agents/{agent_id}")
async def delete_dashboard_agent(agent_id: str):
    dashboard_repository.remove_agent(agent_id)
    return {"status": "success"}

