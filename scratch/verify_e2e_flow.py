"""
End-to-end verification script testing the live HTTP endpoints for ORACLE 5.0.
"""
import urllib.request
import json
import os

BASE_URL = "http://127.0.0.1:8000"

def post_json(path: str, data: dict) -> dict:
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def get_json(path: str) -> dict:
    url = f"{BASE_URL}{path}"
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode("utf-8"))

def test_e2e():
    repo_path = os.path.abspath("tests/test_repos/evaluation_repo")
    print(f"Testing against real repository: {repo_path}")

    # 1. Test repository inspect endpoint
    inspect_res = post_json("/api/v1/repositories/inspect", {"repository_path": repo_path})
    inv = inspect_res.get("inventory", {})
    print("\n[1] Repository Inspection:")
    print(f"  Languages: {inv.get('languages')}")
    print(f"  Frameworks: {inv.get('frameworks')}")
    print(f"  Files Indexed: {inv.get('total_files')}")
    print(f"  Head Commit: {inv.get('git_head_commit')}")
    assert "Python" in inv.get("languages", [])

    # 2. Test Bug B: Redis Cache Key Regression
    error_trace_b = """TypeError: 'NoneType' object is not subscriptable
    at payment_service.py:184 in process_payment
    at checkout.py:52 in handle_checkout"""
    
    logs_b = """2026-04-02T14:32:01.102Z [req_8472] [WARN] Cache MISS for key 'customer:v2:usr_9981' in Redis
2026-04-02T14:32:01.105Z [req_8472] [ERROR] Uncaught exception in payment_service.py:184: TypeError"""

    res_b = post_json("/api/v1/investigations", {
        "title": "Production Incident: Payment authorization failures on customer tier lookup",
        "service": "payment-api",
        "environment": "production",
        "repository": "enterprise/payment-service",
        "repository_path": repo_path,
        "stackTrace": error_trace_b,
        "logs": logs_b,
    })
    inv_id_b = res_b["id"]
    print(f"\n[2] Bug B Created: {inv_id_b}")
    print(f"  Stage: {res_b.get('stage')}")
    print(f"  Confidence: {res_b.get('confidence')}%")
    print(f"  Root Cause Title: {res_b.get('rootCause', {}).get('title')}")
    print(f"  Root Cause Status: {res_b.get('rootCause', {}).get('status')}")
    print(f"  Evidence Count: {len(res_b.get('evidence', []))}")
    print(f"  Repository Inventory: {res_b.get('repositoryInventory') is not None}")
    assert res_b.get("stage") == "ROOT_CAUSE_IDENTIFIED"
    assert res_b.get("confidence") == 94
    assert len(res_b.get("evidence", [])) >= 4

    # Fetch detail endpoints
    rc_detail = get_json(f"/api/v1/investigations/{inv_id_b}/root-cause")
    print(f"  GET /root-cause status: {rc_detail.get('status')}")

    # 3. Test Bug E: Ambiguous Incident (Insufficient Evidence)
    error_trace_e = """RuntimeError: Inconsistent state detected in orchestrator
    at ambiguous_worker.py:42 in dispatch_event"""

    res_e = post_json("/api/v1/investigations", {
        "title": "Incident: Ambiguous upstream worker failure",
        "service": "orchestrator",
        "environment": "production",
        "repository_path": repo_path,
        "stackTrace": error_trace_e,
    })
    inv_id_e = res_e["id"]
    print(f"\n[3] Bug E Created: {inv_id_e}")
    print(f"  Stage: {res_e.get('stage')}")
    print(f"  Confidence: {res_e.get('confidence')}%")
    print(f"  Root Cause Title: {res_e.get('rootCause', {}).get('title')}")
    print(f"  Root Cause Status: {res_e.get('rootCause', {}).get('status')}")
    print(f"  Missing Evidence: {res_e.get('rootCause', {}).get('missingEvidence')}")
    print(f"  Recommended Next Actions: {res_e.get('rootCause', {}).get('recommendedNextActions')}")
    assert res_e.get("stage") == "INSUFFICIENT_EVIDENCE"
    assert res_e.get("confidence") <= 40
    assert len(res_e.get("rootCause", {}).get("missingEvidence", [])) > 0

    print("\nALL LIVE E2E API CHECKS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_e2e()
