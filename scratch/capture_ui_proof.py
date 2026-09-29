"""
Playwright automated UI verification and artifact capture for ORACLE 5.0.
"""
import os
import time
from playwright.sync_api import sync_playwright

ARTIFACT_DIR = r"C:\Users\damer\.gemini\antigravity-ide\brain\c94bf6e3-fda3-4197-8c1b-4821834c7ff3"

def capture_ui():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        print("[1] Opening http://localhost:3000...", flush=True)
        page.goto("http://localhost:3000", wait_until="networkidle")
        time.sleep(1)

        # Screenshot 1: Home / Console
        p1 = os.path.join(ARTIFACT_DIR, "oracle_50_console_home.png")
        page.screenshot(path=p1)
        print(f"Saved: {p1}", flush=True)

        # Navigate to Investigate view
        print("[2] Navigating to Investigate view...", flush=True)
        page.click("nav button:has-text('Investigate')")
        page.wait_for_selector("text=Benchmark Evaluation Presets", timeout=10000)
        time.sleep(0.5)

        # Screenshot 2: Intake form with live repo inspection
        print("[3] Inspecting Bug B preset...", flush=True)
        page.click("button:has-text('Bug B: Cache Key')")
        time.sleep(1)
        p2 = os.path.join(ARTIFACT_DIR, "oracle_50_bug_b_intake.png")
        page.screenshot(path=p2)
        print(f"Saved: {p2}", flush=True)

        # Run Investigation
        print("[4] Submitting real investigation...", flush=True)
        page.click("button:has-text('Start Real Investigation')")
        page.wait_for_selector("text=Topology", timeout=15000)
        time.sleep(1.5)

        # Screenshot 3: Workspace Overview
        p3 = os.path.join(ARTIFACT_DIR, "oracle_50_workspace_overview.png")
        page.screenshot(path=p3)
        print(f"Saved: {p3}", flush=True)

        # Switch to Evidence tab
        print("[5] Inspecting Evidence Vault...", flush=True)
        page.click("div.border-b button:has-text('Evidence')")
        time.sleep(1)
        p4 = os.path.join(ARTIFACT_DIR, "oracle_50_evidence_vault.png")
        page.screenshot(path=p4)
        print(f"Saved: {p4}", flush=True)

        # Switch to Root Cause tab
        print("[6] Inspecting Root Cause determination...", flush=True)
        page.click("div.border-b button:has-text('Root Cause')")
        time.sleep(1)
        p5 = os.path.join(ARTIFACT_DIR, "oracle_50_root_cause.png")
        page.screenshot(path=p5)
        print(f"Saved: {p5}", flush=True)

        # Switch to Agent Task tab
        print("[7] Inspecting Agent Task generation...", flush=True)
        page.click("div.border-b button:has-text('Agent Task')")
        time.sleep(1)
        p6 = os.path.join(ARTIFACT_DIR, "oracle_50_agent_task.png")
        page.screenshot(path=p6)
        print(f"Saved: {p6}", flush=True)

        # Test Bug E: Insufficient Evidence
        print("[8] Testing Bug E: Insufficient Evidence...", flush=True)
        page.click("nav button:has-text('Investigate')")
        page.wait_for_selector("text=Benchmark Evaluation Presets", timeout=10000)
        time.sleep(0.5)
        page.click("button:has-text('Bug E: Ambiguous')")
        time.sleep(1)
        page.click("button:has-text('Start Real Investigation')")
        page.wait_for_selector("text=Topology", timeout=15000)
        time.sleep(1.5)

        # View Insufficient Evidence in Root Cause tab
        page.click("div.border-b button:has-text('Root Cause')")
        time.sleep(1)
        p7 = os.path.join(ARTIFACT_DIR, "oracle_50_insufficient_evidence.png")
        page.screenshot(path=p7)
        print(f"Saved: {p7}", flush=True)

        browser.close()
        print("\nALL SCREENSHOTS CAPTURED SUCCESSFULLY!", flush=True)

if __name__ == "__main__":
    capture_ui()
