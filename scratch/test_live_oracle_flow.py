import os
import sys
from pathlib import Path
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

load_dotenv()
import httpx

print("=" * 70)
print("ORACLE END-TO-END LIVE INTEGRATION DEMO (FASTAPI + JIRA + GITHUB)")
print("=" * 70)

client = httpx.Client(base_url="http://127.0.0.1:8000/api/v1", timeout=30.0)

# 1. Health & Persistence Check
h = client.get("/health")
print(f"\n[1] Backend Health: {h.status_code}")
print(f"    Payload: {h.json()}")

# 2. Query Live System Metrics
m = client.get("/system/metrics")
print(f"\n[2] System Metrics: {m.status_code}")
print(f"    Metrics: {m.json()}")

# 3. Create a Live Investigation targeting user's real Jira issue KAN-4 and GitHub repo
payload = {
    "title": "KAN-4: Authentication token validation failure during customer login",
    "service": "auth-service",
    "environment": "production",
    "repository": "SrimanthReddyDamera/aim-Oracle",
    "commit": "8f31a2c9",
    "branch": "main",
    "deployment": "v3.1.4",
    "cloudProvider": "aws-us-east-1",
    "timeRange": "Past 30 minutes",
    "stackTrace": """2026-09-29T14:40:12.102Z [CRITICAL] auth_service.py:142: verify_jwt_token() raised TokenExpiredError
Traceback (most recent call last):
  File "backend/release/security.py", line 142, in verify_jwt_token
    claims = jwt.decode(token, key, algorithms=["EdDSA"])
jwt.exceptions.ExpiredSignatureError: Signature has expired
during handling of the above exception:
AuthSessionError: Active session for KAN-4 invalid on auth cluster""",
    "additionalNotes": "Correlated to Jira ticket KAN-4 and repository SrimanthReddyDamera/aim-Oracle.",
    "selectedSources": ["jira", "github", "apm", "logs"]
}

print("\n[3] Triggering Real Autonomous AI Investigation for KAN-4...")
create_res = client.post("/investigations", json=payload)
print(f"    Create Status: {create_res.status_code}")
inv = create_res.json()
inv_id = inv.get("id") or inv.get("investigation_id")
print(f"    Created Investigation ID: {inv_id}")
print(f"    Incident Title:          {inv.get('title')}")
print(f"    Stage:                   {inv.get('stage')}")
print(f"    Confidence:              {inv.get('confidence')}%")
print(f"    Jira Key:                {inv.get('jiraKey')}")
print(f"    Repository:              {inv.get('context', {}).get('repository')}")

# 4. Trigger Sandbox Verification Replay Gate
print(f"\n[4] Executing Sandbox Verification Gate for {inv_id}...")
verify_res = client.post(f"/investigations/{inv_id}/verify", json={"outcome": "VERIFIED"})
print(f"    Verification Status: {verify_res.status_code}")
v_data = verify_res.json()
print(f"    Verdict:   {v_data.get('status')}")
print(f"    Gate Msg:  {v_data.get('verdictMessage')}")
if v_data.get("attestation"):
    att = v_data["attestation"]
    print(f"    Cryptographic Digest: {att.get('digest')}")
    print(f"    Gate Attestation:    {att.get('gateStatus')}")

print("\n" + "=" * 70)
print("LIVE END-TO-END PIPELINE DEMONSTRATION COMPLETE")
print("=" * 70)
