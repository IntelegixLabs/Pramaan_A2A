package agentsecgov

default decision = {
  "decision": "deny",
  "reason": "no allow rule matched"
}

has_scope(scope) {
  input.principal.scopes[_] == scope
}

# --- HR Department Rules ---
decision = {
  "decision": "allow",
  "reason": "HR member executing HR relocation action"
} {
  input.principal.department == "HR"
  input.tool.name == "finance.disburse.relocation"
  input.tool.risk == "low"
  has_scope("finance.disburse.relocation")
}

decision = {
  "decision": "review",
  "reason": "HR member executing high-risk relocation action requires review"
} {
  input.principal.department == "HR"
  input.tool.name == "finance.disburse.relocation"
  input.tool.risk == "high"
  has_scope("finance.disburse.relocation")
}

# --- Finance Department Rules ---
decision = {
  "decision": "allow",
  "reason": "Finance member executing payroll action"
} {
  input.principal.department == "Finance"
  input.tool.name == "finance.process_payroll"
  has_scope("finance.process_payroll")
}

# --- Goal Integrity Checks ---
decision = {
  "decision": "deny",
  "reason": "goal mismatch: tool execution does not align with user intent"
} {
  input.context.goal_match == false
}

# --- General Low Risk ---
decision = {
  "decision": "allow",
  "reason": "low-risk scoped action allowed"
} {
  input.tool.risk == "low"
  has_scope(input.tool.required_scope)
}

# --- Critical Actions ---
# Always deny critical actions unless they have breakglass scope
decision = {
  "decision": "deny",
  "reason": "critical tool without breakglass scope"
} {
  input.tool.risk == "critical"
  not has_scope("breakglass:critical")
}
