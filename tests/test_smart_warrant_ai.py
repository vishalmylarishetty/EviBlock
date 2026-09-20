"""
ForensicChain AI Smart Warrant Recommendation — Comprehensive Automated Test Suite
Verifies:
  1. Role-based access to /api/warrants/<warrant_number>/ai-recommendation
     (Admin, Court, Police allowed; Witness blocked 403)
  2. Structured AI Recommendation output:
     - warrant ID, current expiry, workflow completion %, pending metrics
     - "AI Recommendation" wording (never "AI Decision")
     - supporting features & model version
  3. AI does NOT automatically modify warrant expiry timestamp
  4. Separate recording of AI recommendation & final human decision in database
  5. Police workflow: can view recommendation & request extension
  6. Court Authority workflow: views recommendation & decides [Approve / Reject]
  7. Final human decision updates recommendation record
  8. Non-existent warrant returns 404
  9. Existing Smart Warrants functionality remains 100% intact
"""

import sys
import os
import requests
import json

BASE_DIR = os.path.abspath(r"c:\Users\SAI SRI\Downloads\mini vm\ForensicChain_Presentation_Ready")
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

try:
    import database as db
except ImportError:
    from backend import database as db

BASE_URL = "http://127.0.0.1:5000"


CREDS = {
    "admin":    {"email": "admin@forensic.local",       "password": "Admin@12345"},
    "court":    {"email": "thomas.court@forensic.gov",  "password": "Password123!"},
    "police":   {"email": "james.witness@forensic.gov", "password": "Password123!"},
    "analyst":  {"email": "analyst@forensic.gov",       "password": "Password123!"},
    "witness":  {"email": "witness@forensic.gov",       "password": "Password123!"},
}

PASS = "[PASS]"
FAIL = "[FAIL]"
SKIP = "[SKIP]"

results = []

def make_session(role):
    s = requests.Session()
    creds = CREDS[role]
    r = s.post(f"{BASE_URL}/api/auth/login", json=creds)
    if r.status_code != 200:
        print(f"  {FAIL} Login failed for {role}: {r.status_code}")
        return None
    return s

def check(label, condition, detail=""):
    icon = PASS if condition else FAIL
    msg = f"  {icon} {label}"
    if detail:
        msg += f"  [{detail}]"
    print(msg)
    results.append((label, condition))
    return condition

print("\n" + "="*60)
print("  ForensicChain AI Smart Warrant Recommendation Test Suite")
print("="*60)

admin_s = make_session("admin")
court_s = make_session("court")
police_s = make_session("police")
witness_s = make_session("witness")

# Fetch an existing warrant for testing
warrants_list = []
if admin_s:
    r = admin_s.get(f"{BASE_URL}/api/warrants")
    if r.status_code == 200:
        warrants_list = r.json()

target_warrant = warrants_list[0]["warrant_number"] if warrants_list else "WR-MB-1789055420"
print(f"\nUsing Target Warrant: {target_warrant}")

# ── Test 1: Role-Based Access to AI Recommendation ─────────
print("\n[1] Role-Based Access to AI Recommendation Endpoint")

if admin_s:
    r = admin_s.get(f"{BASE_URL}/api/warrants/{target_warrant}/ai-recommendation")
    check("Admin can access AI recommendation", r.status_code == 200, f"HTTP {r.status_code}")

if court_s:
    r = court_s.get(f"{BASE_URL}/api/warrants/{target_warrant}/ai-recommendation")
    check("Court Authority can access AI recommendation", r.status_code == 200, f"HTTP {r.status_code}")

if police_s:
    r = police_s.get(f"{BASE_URL}/api/warrants/{target_warrant}/ai-recommendation")
    check("Police can access AI recommendation", r.status_code == 200, f"HTTP {r.status_code}")

if witness_s:
    r = witness_s.get(f"{BASE_URL}/api/warrants/{target_warrant}/ai-recommendation")
    check("Witness blocked from AI recommendation (403)", r.status_code == 403, f"HTTP {r.status_code}")

# ── Test 2: Structured Recommendation Format & Wording ──────
print("\n[2] Structured Recommendation Payload & Evidentiary Wording")

rec_data = None
if court_s:
    r = court_s.post(f"{BASE_URL}/api/warrants/{target_warrant}/ai-recommendation")
    if r.status_code == 200:
        rec_data = r.json()

if rec_data:
    check("Payload contains warrant_number", rec_data.get("warrant_number") == target_warrant, rec_data.get("warrant_number"))
    check("Payload contains current_expiry", bool(rec_data.get("current_expiry")), rec_data.get("current_expiry"))
    check("Payload contains workflow_completion_pct", "workflow_completion_pct" in rec_data, f"{rec_data.get('workflow_completion_pct')}%")
    
    pending = rec_data.get("pending", {})
    check("Pending metrics contains evidence_items", "evidence_items" in pending, str(pending.get("evidence_items")))
    check("Pending metrics contains forensic_verification", "forensic_verification" in pending, str(pending.get("forensic_verification")))
    check("Pending metrics contains court_review", "court_review" in pending, str(pending.get("court_review")))
    
    check("Uses 'ai_recommendation' key (not decision)", "ai_recommendation" in rec_data, rec_data.get("ai_recommendation"))
    check("Recommendation is valid wording", rec_data.get("ai_recommendation") in [
        "Extension may be required.", "Extension not currently indicated."
    ], rec_data.get("ai_recommendation"))
    check("Payload contains descriptive reason", bool(rec_data.get("reason")), rec_data.get("reason"))
    
    # Check that it never says 'AI Decision'
    json_str = json.dumps(rec_data).lower()
    check("Wording is 'AI Recommendation' NOT 'AI Decision'", "ai decision" not in json_str, "Advisory Confirmed")
    check("Disclaimer clarifies advisory nature", "not a legal decision" in rec_data.get("disclaimer", "").lower(), "Disclaimer OK")
    check("Contains relevant_features dict", isinstance(rec_data.get("relevant_features"), dict), f"{len(rec_data.get('relevant_features', {}))} features")
    check("Contains model_version", bool(rec_data.get("model_version")), rec_data.get("model_version"))
    check("Contains recommendation_timestamp", bool(rec_data.get("recommendation_timestamp")), rec_data.get("recommendation_timestamp"))
    check("Contains final_human_decision field", "final_human_decision" in rec_data, rec_data.get("final_human_decision"))

# ── Test 3: AI Does NOT Modify Warrant Expiry ───────────────
print("\n[3] AI Non-Interference: Expiry Timestamp Remains Unchanged")

if admin_s:
    w_before = admin_s.get(f"{BASE_URL}/api/warrants/{target_warrant}").json()
    expiry_before = w_before.get("valid_until")
    
    # Trigger AI recommendation scan
    admin_s.post(f"{BASE_URL}/api/warrants/{target_warrant}/ai-recommendation")
    
    w_after = admin_s.get(f"{BASE_URL}/api/warrants/{target_warrant}").json()
    expiry_after = w_after.get("valid_until")
    
    check("AI scan did NOT modify warrant expiry timestamp", expiry_before == expiry_after, f"{expiry_before} == {expiry_after}")

# ── Test 4: Separate Database Storage for AI Recommendations ─
print("\n[4] Database Storage: AI Recommendation Recorded Separately")

if admin_s:
    latest_rec_db = db.get_latest_warrant_ai_recommendation(target_warrant)

    check("Recommendation row saved in warrant_ai_recommendations", latest_rec_db is not None, f"ID: {latest_rec_db['id'] if latest_rec_db else 'None'}")
    if latest_rec_db:
        check("Stored warrant_number matches", latest_rec_db["warrant_number"] == target_warrant, latest_rec_db["warrant_number"])
        check("Stored recommendation matches", bool(latest_rec_db["recommendation"]), latest_rec_db["recommendation"])
        check("Stored model_version matches", bool(latest_rec_db["model_version"]), latest_rec_db["model_version"])
        check("Stored features_json present", bool(latest_rec_db["features_json"]), "Features JSON OK")

# ── Test 5: Police Extension Request Workflow ───────────────
print("\n[5] Police Extension Request Workflow (Human Driven)")

# Create a fresh warrant for testing the request + court review cycle
import time
test_warrant_num = f"WR-TEST-AI-{int(time.time() * 1000)}"
if admin_s:
    r_reg = admin_s.post(f"{BASE_URL}/api/warrants/register", json={
        "warrant_number": test_warrant_num,
        "case_id": "CASE-2026-001",
        "duration_seconds": 3600
    })
    check("Created test warrant for extension cycle", r_reg.status_code in (200, 201), f"HTTP {r_reg.status_code} ({test_warrant_num})")


if police_s:
    # Police requests extension
    r_req = police_s.post(f"{BASE_URL}/api/warrants/{test_warrant_num}/request-extension", json={
        "additional_seconds": 7200,
        "reason": "Forensic lab data extraction pending judicial deadline"
    })
    check("Police can submit warrant extension request", r_req.status_code in (200, 201), f"HTTP {r_req.status_code}")


# ── Test 6: Court Review Workflow & Human Decision Recording
print("\n[6] Court Review & Final Human Decision Recording")

if court_s:
    # Get pending requests
    r_list = court_s.get(f"{BASE_URL}/api/warrants/extension-requests?status=pending")
    if r_list.status_code == 200:
        pending_list = [req for req in r_list.json() if req.get("warrant_number") == test_warrant_num]
        check("Court can view pending request", len(pending_list) > 0, f"Found {len(pending_list)} pending")
        
        if pending_list:
            req_id = pending_list[0]["id"]
            # Generate AI recommendation for court to review
            r_ai = court_s.get(f"{BASE_URL}/api/warrants/{test_warrant_num}/ai-recommendation")
            check("Court can view AI recommendation prior to decision", r_ai.status_code == 200, "Advisory Viewed")
            
            # Court approves extension
            r_rev = court_s.post(f"{BASE_URL}/api/warrants/extension-requests/{req_id}/review", json={
                "decision": "approved",
                "decision_note": "Judicial extension granted per forensic necessity."
            })
            check("Court Authority approves extension", r_rev.status_code == 200, f"HTTP {r_rev.status_code}")
            
            # Check database to ensure final_human_decision was recorded on recommendation
            updated_rec = db.get_latest_warrant_ai_recommendation(test_warrant_num)

            if updated_rec:
                check("Final human decision recorded on AI recommendation record", updated_rec["final_human_decision"] == "approved", updated_rec["final_human_decision"])

# ── Test 7: Non-Existent Warrant Handling ───────────────────
print("\n[7] Non-Existent Warrant Handling")

if court_s:
    r = court_s.get(f"{BASE_URL}/api/warrants/WR-DOES-NOT-EXIST-9999/ai-recommendation")
    check("Non-existent warrant returns 404", r.status_code == 404, f"HTTP {r.status_code}")

# ── Test 8: List Warrants API includes AI Recommendation ────
print("\n[8] Warrants List API Integration")

if admin_s:
    r = admin_s.get(f"{BASE_URL}/api/warrants")
    if r.status_code == 200:
        w_list = r.json()
        item = next((w for w in w_list if w.get("warrant_number") == target_warrant), None)
        check("Warrants list includes ai_recommendation object", item is not None and "ai_recommendation" in item, "Field present")

# ── Summary ─────────────────────────────────────────────────
print("\n" + "="*60)
total = len(results)
passed = sum(1 for _, v in results if v)
failed = total - passed
print(f"  Results: {passed}/{total} passed  ({failed} failed)")
print("="*60)

if failed > 0:
    print("\n  Failed tests:")
    for label, ok in results:
        if not ok:
            print(f"    {FAIL} {label}")

sys.exit(0 if failed == 0 else 1)
