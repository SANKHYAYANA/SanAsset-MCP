"""
server.py — MCP Server for SanAsset_MCP

This is the SERVER. It listens on port 8000 and waits for tool calls from any client.

How it works:
  1. Client sends JSON request → { "method": "tools/call", "params": { "name": "authenticate_user", "arguments": {"api_key": "..."} } }
  2. Server sees tool name → routes to the correct function
  3. Function reads CSV files → does the work → returns result
  4. Server wraps result in JSON → { "result": { "content": [{"type": "text", "text": "✅ PASSED..."}] } }
  5. Sends JSON response back to client

Run: python server.py
     (starts SSE server on http://localhost:8000)
"""

import csv
import os
from datetime import datetime
from mcp.server.mcpserver import MCPServer as FastMCP

# Path to data folder (same folder as this script + /data)
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

# Create MCP server instance — this handles all the JSON routing for us
mcp = FastMCP("SanAsset-MCP")


# ============================================================
#  HELPER — audit logging (writes to audit_log.csv)
# ============================================================

def _mask_key(api_key):
    """
    Hides the API key for security — shows only first 4 and last 3 characters.

    "sk_admin_001" → "sk_a***001"

    Why? We log who did what, but we don't want full API keys in the log file.
    If someone reads the log, they can't steal the key.
    """
    if len(api_key) <= 7:
        return "***"
    return api_key[:4] + "***" + api_key[-3:]


def _log_audit(api_key, tool_used, parameters, status):
    """
    Appends one row to audit_log.csv.

    Called EVERY time a tool runs — whether it succeeded or failed.
    This is the CCTV camera — records everything.

    CSV columns: timestamp, emp_id, username, api_key (masked), tool_used, parameters, status
    """
    filepath = os.path.join(DATA_DIR, "audit_log.csv")

    # Get user info from api_key (might be None if invalid key)
    user = _read_credentials(api_key)

    # Build the log row
    row = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # current date and time
        "emp_id": user["emp_id"] if user else "UNKNOWN",            # who did it
        "username": user["username"] if user else "UNKNOWN",         # their name
        "api_key": _mask_key(api_key),                               # masked key for security
        "tool_used": tool_used,                                      # which tool was called
        "parameters": parameters,                                     # what parameters were sent
        "status": status                                              # success or denied or failed
    }

    # Append to CSV file (don't overwrite, just add new row at the end)
    with open(filepath, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        writer.writerow(row)


# ============================================================
#  HELPER — reads credentials.csv (not a tool, just internal)
# ============================================================

def _read_credentials(api_key):
    """
    Opens credentials.csv, searches for the api_key.

    Returns dict if found AND status is active:
        {"emp_id": "E001", "username": "sankhyayana", "role": "admin"}

    Returns None if:
        - api_key not found in CSV
        - api_key found but status is "blocked"
    """
    filepath = os.path.join(DATA_DIR, "credentials.csv")

    with open(filepath, "r") as f:
        reader = csv.DictReader(f)  # reads CSV as list of dicts, using header row as keys
        for row in reader:
            # row = {"api_key": "sk_admin_001", "emp_id": "E001", "username": "sankhyayana", "role": "admin", "status": "active", ...}
            if row["api_key"] == api_key and row["status"] == "active":
                return {
                    "emp_id": row["emp_id"],
                    "username": row["username"],
                    "role": row["role"]
                }

    # Reached end of CSV without finding a match
    return None


# ============================================================
#  TOOL — authenticate_user
#  This is what the client calls via MCP protocol
#  @mcp.tool() registers it so server knows this function exists
# ============================================================

@mcp.tool()
def authenticate_user(api_key: str) -> str:
    """Login with API key. Returns your name, role, and emp_id if valid."""

    # Step 1: Check the API key against credentials.csv
    user = _read_credentials(api_key)

    # Step 2: Build response string + audit log
    if user:
        _log_audit(api_key, "authenticate_user", "", "success")
        return f"✅ PASSED — Welcome {user['username']}! Role: {user['role']}, Emp ID: {user['emp_id']}"
    else:
        _log_audit(api_key, "authenticate_user", "", "failed")
        return "❌ FAILED — Invalid API key"


# ============================================================
#  HELPER — reads employees.csv (not a tool, just internal)
# ============================================================

def _read_employee(emp_id):
    """
    Opens employees.csv, searches for the emp_id.

    Returns dict if found:
        {"emp_id": "E002", "name": "Vikram Sharma", "department": "Site IT", ...}

    Returns None if emp_id not found in CSV.
    """
    filepath = os.path.join(DATA_DIR, "employees.csv")

    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # row = {"emp_id": "E002", "name": "Vikram Sharma", "department": "Site IT", "designation": "IT Manager", ...}
            if row["emp_id"] == emp_id:
                return dict(row)  # return the full row as a dict

    # emp_id not found
    return None


# ============================================================
#  TOOL — get_my_details
#  Client calls this AFTER authenticate_user passes
#  Uses the same api_key → finds emp_id from credentials.csv
#  Then uses emp_id → finds employee row from employees.csv
# ============================================================

@mcp.tool()
def get_my_details(api_key: str) -> str:
    """Get YOUR OWN employee details only. Do NOT use this to look up other employees — use search_employee instead."""

    # Step 1: Validate the API key
    user = _read_credentials(api_key)

    if not user:
        _log_audit(api_key, "get_my_details", "", "failed")
        return "❌ FAILED — Invalid API key"

    # Step 2: Use emp_id from credentials to find YOUR employee row
    employee = _read_employee(user["emp_id"])

    if not employee:
        _log_audit(api_key, "get_my_details", "", "not_found")
        return f"❌ Employee {user['emp_id']} not found in employees.csv"

    # Step 3: Audit log + build response
    _log_audit(api_key, "get_my_details", "", "success")
    return (
        f"📋 Your Details:\n"
        f"   Name: {employee['name']}\n"
        f"   Emp ID: {employee['emp_id']}\n"
        f"   Department: {employee['department']}\n"
        f"   Designation: {employee['designation']}\n"
        f"   Manager ID: {employee['manager_id']}\n"
        f"   Join Date: {employee['join_date']}\n"
        f"   Phone: {employee['phone']}"
    )


# ============================================================
#  HELPER — reads ALL rows from employees.csv
# ============================================================

def _read_all_employees():
    """
    Opens employees.csv, reads ALL rows.

    Returns list of dicts:
        [{"emp_id": "E001", "name": "Sankhyayana", ...}, {"emp_id": "E002", ...}, ...]
    """
    filepath = os.path.join(DATA_DIR, "employees.csv")
    employees = []

    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            employees.append(dict(row))

    return employees


# ============================================================
#  TOOL — search_employee
#  ONE tool that replaces both get_employee_details AND list_employees
#
#  How it works:
#    query=""         → list everyone in your scope (like old list_employees)
#    query="Kavita"   → search by name
#    query="E017"     → search by emp_id
#    query="Designer" → search by designation
#    query="Site IT"  → search by department
#
#  RBAC (same as before):
#    admin    → searches ALL 26 employees
#    manager  → searches only their team members
#    employee → searches only themselves
#
#  The search is case-insensitive so "kavita" and "Kavita" both work
# ============================================================

@mcp.tool()
def search_employee(api_key: str, query: str = "") -> str:
    """Search employees by name, emp_id, department, or designation. Leave query empty to list all in your scope. Admin sees all, manager sees their team, employee sees only themselves."""

    # Step 1: Validate API key — who is asking?
    user = _read_credentials(api_key)

    if not user:
        _log_audit(api_key, "search_employee", f"query={query}", "failed")
        return "❌ FAILED — Invalid API key"

    # Step 2: Read all employees from CSV
    all_employees = _read_all_employees()

    # Step 3: RBAC — filter to only employees this person is ALLOWED to see
    #   This is the OUTER IF — role check
    #   admin    → can see everyone (no filter)
    #   manager  → can see only their team (manager_id matches their emp_id) + themselves
    #   employee → can see only themselves

    if user["role"] == "admin":
        # Admin sees everyone — no filter needed
        scope = all_employees

    elif user["role"] == "manager":
        # Manager sees their team + themselves
        # "their team" = employees whose manager_id == this manager's emp_id
        scope = [
            emp for emp in all_employees
            if emp["manager_id"] == user["emp_id"] or emp["emp_id"] == user["emp_id"]
        ]

    else:
        # Employee sees only themselves
        scope = [
            emp for emp in all_employees
            if emp["emp_id"] == user["emp_id"]
        ]

    # Step 4: INNER IF — search within the allowed scope
    #   If query is empty → return all in scope (list mode)
    #   If query has value → search across 4 fields (search mode)

    if query.strip() == "":
        # No query → list everyone in scope
        matches = scope
    else:
        # Search across name, emp_id, department, designation
        # .lower() makes it case-insensitive
        q = query.strip().lower()
        matches = [
            emp for emp in scope
            if q in emp["name"].lower()
            or q in emp["emp_id"].lower()
            or q in emp["department"].lower()
            or q in emp["designation"].lower()
        ]

    # Step 5: Audit log
    _log_audit(api_key, "search_employee", f"query={query}", "success")

    # Step 6: Build response
    if not matches:
        if query.strip() == "":
            return "No employees found in your scope."
        else:
            return f"🔍 No employees found matching '{query}' in your scope."

    # Build detailed output — show ALL 7 fields for each match
    result = f"🔍 Found {len(matches)} employee(s)"
    if query.strip():
        result += f" matching '{query}'"
    result += ":\n\n"

    for emp in matches:
        result += (
            f"   Name: {emp['name']}\n"
            f"   Emp ID: {emp['emp_id']}\n"
            f"   Department: {emp['department']}\n"
            f"   Designation: {emp['designation']}\n"
            f"   Manager ID: {emp['manager_id']}\n"
            f"   Join Date: {emp['join_date']}\n"
            f"   Phone: {emp['phone']}\n"
            f"   ---\n"
        )

    return result



# ============================================================
#  TOOL — view_audit_log
#  Shows who did what and when
#  RBAC: admin only — no one else can see the logs
# ============================================================

@mcp.tool()
def view_audit_log(api_key: str, limit: str = "20") -> str:
    """View recent audit log entries showing who did what and when. Admin only. Default shows last 20 entries."""

    # Step 1: Validate API key
    user = _read_credentials(api_key)

    if not user:
        return "❌ FAILED — Invalid API key"

    # Step 2: OUTER IF — only admin can view audit logs
    if user["role"] != "admin":
        _log_audit(api_key, "view_audit_log", "", "denied")
        return "❌ You don't have access to view audit logs. Admin only."

    # Step 3: Read audit_log.csv
    filepath = os.path.join(DATA_DIR, "audit_log.csv")
    logs = []

    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            logs.append(dict(row))

    # Step 4: Get last N entries (most recent at bottom of CSV)
    limit_num = int(limit)
    recent_logs = logs[-limit_num:] if len(logs) > limit_num else logs

    # Step 5: Audit log this action too
    _log_audit(api_key, "view_audit_log", f"limit={limit}", "success")

    # Step 6: Build response
    if not recent_logs:
        return "📜 Audit log is empty."

    result = f"📜 Audit Log (last {len(recent_logs)} entries):\n"
    for log in recent_logs:
        result += f"   {log['timestamp']} | {log['username']} | {log['tool_used']} | {log['parameters']} | {log['status']}\n"

    return result




# ============================================================
#  START SERVER
#  When you run "python server.py", this block executes
#  mcp.run() starts listening for incoming requests
#
#  PORT logic:
#    - On Railway/cloud: reads PORT from environment variable (Railway sets this)
#    - On your PC:       defaults to 8000 if no PORT env variable found
# ============================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))

    print(f"Starting SanAsset-MCP server on http://0.0.0.0:{port}")
    print(f"Agent connects to: http://localhost:{port}/sse")
    print("4 tools loaded: authenticate_user, get_my_details, search_employee, view_audit_log")
    print("Waiting for connections...")

    # transport="sse" → listens over HTTP (network)
    # host="0.0.0.0"  → accepts connections from any IP
    # port=dynamic     → reads from PORT env variable, or 8000 locally
    mcp.run(transport="sse", host="0.0.0.0", port=port)