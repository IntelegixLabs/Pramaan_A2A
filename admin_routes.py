from fastapi import APIRouter, HTTPException
from typing import List, Dict

from security.pii_redactor import pii_redactor
from security.goal_checker import goal_checker
from security.output_validator import output_validator
from security.sandbox import sandbox
from security.authorization import authorization_engine
from security.human_review import human_review_queue

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

