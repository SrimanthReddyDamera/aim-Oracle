import requests
import json
from pathlib import Path

base_url = "http://127.0.0.1:8000"

repo_path = str(Path("tests/test_repos/evaluation_repo").resolve())

create_payload = {
    "title": "Production Null Subscript in PaymentService",
    "stackTrace": """Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
TypeError: 'NoneType' object is not subscriptable""",
    "service": "payment-service",
    "environment": "production",
    "repository_path": repo_path,
}

resp = requests.post(f"{base_url}/api/v1/investigations", json=create_payload)
print("INVESTIGATION STATUS:", resp.status_code)
inv_data = resp.json()
inv_id = inv_data.get("id") or inv_data.get("investigation_id")
print("INVESTIGATION ID:", inv_id)

verify_resp = requests.post(
    f"{base_url}/api/v1/investigations/{inv_id}/verify",
    json={"outcome": "VERIFIED"}
)
print("VERIFY STATUS CODE:", verify_resp.status_code)
v_data = verify_resp.json()
verification = v_data.get("verification", {})

print("=== LIVE VERIFICATION SUMMARY ===")
print("Status              :", verification.get("status"))
print("Stage               :", verification.get("stage"))
print("Is Real Sandbox     :", verification.get("isRealSandbox"))
print("Deployment Cleared  :", verification.get("deploymentCleared"))
print("Error Eliminated    :", verification.get("originalErrorEliminated"))
print("Regression Passed   :", verification.get("regressionTestsPassed"))
print("Scope Contained     :", verification.get("scopeContained"))
print("Attestation Token   :", verification.get("attestation", {}).get("token"))
print("Attestation Signer  :", verification.get("attestation", {}).get("signer"))
print("Is Mock Demo        :", verification.get("attestation", {}).get("isMockDemo"))
sig = verification.get("attestation", {}).get("signatureHex")
print("Signature Hex       :", sig[:32] + "..." if sig else None)
pub = verification.get("attestation", {}).get("publicKeyHex")
print("Public Key Hex      :", pub[:32] + "..." if pub else None)

# Also test GET /api/v1/verifications/{id}
v_id = verification.get("verificationId")
if v_id:
    get_v = requests.get(f"{base_url}/api/v1/verifications/{v_id}")
    print("GET /verifications/{id} Status:", get_v.status_code)
    att_v = requests.get(f"{base_url}/api/v1/verifications/{v_id}/attestation")
    print("GET /verifications/{id}/attestation Status:", att_v.status_code)
    scope_v = requests.get(f"{base_url}/api/v1/verifications/{v_id}/scope")
    print("GET /verifications/{id}/scope Status:", scope_v.status_code)
    art_v = requests.get(f"{base_url}/api/v1/verifications/{v_id}/artifacts")
    print("GET /verifications/{id}/artifacts Status:", art_v.status_code)
