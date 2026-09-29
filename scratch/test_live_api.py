import urllib.request
import json

payload = {
    "title": "Payment API returning 500 errors",
    "service": "payment-api",
    "environment": "production",
    "repository_path": "tests/test_repos/evaluation_repo",
    "stackTrace": """Traceback (most recent call last):
  File "src/payment/payment_service.py", line 184, in process_payment
    customer_tier = customer["tier"]
TypeError: 'NoneType' object is not subscriptable""",
    "logs": "2026-09-14T08:24:11.402Z [ERROR] payment-api payment_service.py:184: get_customer() returned None\n2026-09-14T08:24:11.403Z [WARN] payment-api Redis MISS customer:8472",
}

req = urllib.request.Request(
    "http://127.0.0.1:8000/api/v1/investigations",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)

res = urllib.request.urlopen(req)
out = json.loads(res.read().decode("utf-8"))

print("=== REAL INVESTIGATION CREATED ===")
print("ID:", out.get("id"))
print("Stage:", out.get("stage"))
print("Confidence:", out.get("confidence"))
print("Root Cause:", out.get("rootCause", {}).get("title"))
print("Evidence Count:", len(out.get("evidence", [])))
print("Resolution Steps:", len(out.get("resolution", {}).get("steps", [])))

# Verify readback
inv_id = out["id"]
req_get = urllib.request.Request(f"http://127.0.0.1:8000/api/v1/investigations/{inv_id}")
res_get = urllib.request.urlopen(req_get)
out_get = json.loads(res_get.read().decode("utf-8"))
print("Readback successful:", out_get["id"] == inv_id)

# Verify detail endpoint
req_rc = urllib.request.Request(f"http://127.0.0.1:8000/api/v1/investigations/{inv_id}/root-cause")
res_rc = urllib.request.urlopen(req_rc)
out_rc = json.loads(res_rc.read().decode("utf-8"))
print("Root Cause endpoint returned:", out_rc.get("root_cause", {}).get("status"))

