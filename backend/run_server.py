"""
ORACLE Backend Ingress Server Runner
Launches the FastAPI ASGI application on port 8000 with durable persistence.
"""

import os
import sys
from pathlib import Path

# Ensure project root is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import uvicorn
from backend.release.ingress import create_ingress_app

app = create_ingress_app()

if __name__ == "__main__":
    print("[ORACLE] Starting Intelligence Control Plane API on http://127.0.0.1:8000 ...")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
    )
