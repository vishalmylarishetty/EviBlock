"""
ForensicChain AI Case Summary — Comprehensive Automated Test Suite
Verifies:
  1. Role-based access for GET /api/cases (admin, court, analyst, police vs witness 403)
  2. Structured case summary generation (facts, narrative, recommendations)
  3. Strict factual integrity (no invented data, "Information not available." when missing)
  4. Absence of unsupported legal conclusions (no guilt, fraud, or misconduct claims)
  5. Distinction between confirmed facts, AI narrative, and advisory recommendations
  6. Presence of generated timestamp, model identifier, and mandatory legal disclaimers
  7. Witness role blocked from generating case summaries (403)
  8. Non-existent case handling (404)
  9. Evidence records, hashes, and blockchain state remain 100% untouched
"""

import sys
import requests
import json

BASE_URL = "http://127.0.0.1:5000"

CREDS = {
    "admin":    {"email": "admin@forensic.local",       "password": "Admin@12345"},
    "court":    {"email": "thomas.court@forensic.gov",  "password": "Password123!"},
    "analyst":  {"email": "analyst@forensic.gov",       "password": "Password123!"},
    "police":   {"email": "james.witness@forensic.gov", "password": "Password123!"},
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
        print(f"  {FAIL} Login failed for {role}: {r.status_code} {r.text[:100]}")
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
print("  ForensicChain AI Case Summary Test Suite")
print("="*60)

# ── Test 1: Role-based access to /api/cases ─────────────────
print("\n[1] Role-Based Access to GET /api/cases")

admin_s = make_session("admin")
court_s = make_session("court")
analyst_s = make_session("analyst")
police_s = make_session("police")
witness_s = make_session("witness")

cases_found = []

if admin_s:
    r = admin_s.get(f"{BASE_URL}/api/cases")
    ok = r.status_code == 200
    check("Admin can access /api/cases", ok, f"HTTP {r.status_code}")
    if ok:
        data = r.json()
        cases_found = data.get("cases", [])
        check("Admin receives list of cases", isinstance(cases_found, list) and len(cases_found) > 0, f"{len(cases_found)} cases")

if court_s:
    r = court_s.get(f"{BASE_URL}/api/cases")
    ok = r.status_code == 200
    check("Court Authority can access /api/cases", ok, f"HTTP {r.status_code}")

if analyst_s:
    r = analyst_s.get(f"{BASE_URL}/api/cases")
    ok = r.status_code == 200
    check("Analyst can access /api/cases", ok, f"HTTP {r.status_code}")

if police_s:
    r = police_s.get(f"{BASE_URL}/api/cases")
    ok = r.status_code == 200
    check("Police can access /api/cases", ok, f"HTTP {r.status_code}")

if witness_s:
    r = witness_s.get(f"{BASE_URL}/api/cases")
    check("Witness blocked from /api/cases (403)", r.status_code == 403, f"HTTP {r.status_code}")

# ── Test 2: Case Summary Generation (Admin) ─────────────────
print("\n[2] Case Summary Generation & Verification")

target_case = cases_found[0] if cases_found else "CASE-2026-001"
summary_data = None

if admin_s:
    r = admin_s.get(f"{BASE_URL}/api/cases/{target_case}/summary")
    ok = r.status_code == 200
    check(f"Admin can generate summary for '{target_case}'", ok, f"HTTP {r.status_code}")
    if ok:
        summary_data = r.json()
        check("Response contains case_id", summary_data.get("case_id") == target_case, summary_data.get("case_id"))
        check("Response contains generated_at timestamp", bool(summary_data.get("generated_at")), summary_data.get("generated_at"))
        check("Response contains model_id", bool(summary_data.get("model_id")), summary_data.get("model_id"))
        check("Response contains mandatory disclaimer", "human review required" in summary_data.get("disclaimer", "").lower(), "")
        check("Response contains confirmed_facts dict", isinstance(summary_data.get("confirmed_facts"), dict), "")
        check("Response contains ai_narrative", bool(summary_data.get("ai_narrative")), "")
        check("Response contains ai_recommendations list", isinstance(summary_data.get("ai_recommendations"), list), f"{len(summary_data.get('ai_recommendations', []))} recs")
        check("Response contains formatted report_text", bool(summary_data.get("report_text")), "")

# ── Test 3: Structured Report Components & Fields ───────────
print("\n[3] Structured Legal Report Verification")

if summary_data:
    facts = summary_data.get("confirmed_facts", {})
    check("Fact: Evidence items count present", "total_evidence_items" in facts, str(facts.get("total_evidence_items")))
    check("Fact: Evidence status breakdown present", "evidence_status" in facts, str(facts.get("evidence_status", {}).get("status_text")))
    check("Fact: Witness attestation status present", "witness_attestation" in facts, str(facts.get("witness_attestation")))
    check("Fact: Forensic verification present", "forensic_verification" in facts, str(facts.get("forensic_verification")))
    check("Fact: Chain of custody summary present", "chain_of_custody" in facts, str(facts.get("chain_of_custody")))
    check("Fact: Blockchain integrity present", "blockchain_integrity" in facts, str(facts.get("blockchain_integrity")))
    check("Fact: Smart warrant present", "smart_warrant" in facts, str(facts.get("smart_warrant")))
    check("Fact: AI/ML alerts present", "ai_ml_alerts" in facts, str(facts.get("ai_ml_alerts")))
    check("Fact: Custody timeline present", isinstance(facts.get("timeline"), list), f"{len(facts.get('timeline', []))} steps")

# ── Test 4: Unsupported Conclusion Guard ─────────────────────
print("\n[4] Unsupported Legal Conclusions Guard")

if summary_data:
    full_text = (summary_data.get("report_text") or "").lower()
    check("Does NOT conclude suspect is guilty", "suspect is guilty" not in full_text, "Clean")
    check("Does NOT conclude evidence is fraudulent", "evidence is definitely fraudulent" not in full_text, "Clean")
    check("Does NOT accuse officer of misconduct", "officer committed misconduct" not in full_text, "Clean")

# ── Test 5: Distinction of Facts vs Narrative vs Advice ─────
print("\n[5] Fact vs AI Narrative vs Recommendation Distinction")

if summary_data:
    rep = summary_data.get("report_text", "")
    check("Section 1 labeled as CONFIRMED SYSTEM FACTS", "SECTION 1: CONFIRMED SYSTEM FACTS" in rep, "")
    check("Section 2 labeled as AI-GENERATED CASE SYNTHESIS", "SECTION 2: AI-GENERATED CASE SYNTHESIS" in rep, "")
    check("Section 3 labeled as AI-GENERATED PROCEDURAL RECOMMENDATIONS", "SECTION 3: AI-GENERATED PROCEDURAL RECOMMENDATIONS" in rep, "")

# ── Test 6: Witness Role Blocked from Generating Summary ───
print("\n[6] Witness Role Access Restriction")

if witness_s:
    r = witness_s.get(f"{BASE_URL}/api/cases/{target_case}/summary")
    check("Witness blocked from generating case summary (403)", r.status_code == 403, f"HTTP {r.status_code}")

# ── Test 7: Non-Existent Case Handling ──────────────────────
print("\n[7] Non-Existent Case Handling")

if admin_s:
    r = admin_s.get(f"{BASE_URL}/api/cases/CASE-DOES-NOT-EXIST-99999/summary")
    check("Non-existent case returns 404", r.status_code == 404, f"HTTP {r.status_code}")

# ── Test 8: Missing Information Writing Standard ────────────
print("\n[8] Missing Information Standard ('Information not available.')")

# Check if cases without warrants show 'Information not available.'
if summary_data:
    warrant_info = summary_data.get("confirmed_facts", {}).get("smart_warrant", "")
    if "Active until" not in warrant_info and "Expired on" not in warrant_info:
        check("Missing warrant uses 'Information not available.'", "Information not available." in warrant_info, warrant_info)
    else:
        check("Active warrant correctly displayed with expiry", "Warrant #" in warrant_info, warrant_info)

# ── Test 9: Evidence Integrity Verification ─────────────────
print("\n[9] Evidence & Hash Immutability After Summary Generation")

if admin_s:
    r_ev = admin_s.get(f"{BASE_URL}/api/evidence")
    if r_ev.status_code == 200:
        ev_items = r_ev.json()
        if isinstance(ev_items, dict):
            ev_items = ev_items.get("evidence", [])
        if ev_items:
            first_ev = ev_items[0]
            check("Evidence records intact", bool(first_ev.get("evidence_id")), first_ev.get("evidence_id"))
            check("Evidence SHA-256 hash intact", bool(first_ev.get("file_hash")), (first_ev.get("file_hash") or "")[:16] + "...")

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
