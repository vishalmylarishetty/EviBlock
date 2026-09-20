"""
ForensicChain ML Anomaly Detection — Comprehensive Test Suite
Tests:
  1. ML status endpoint (role-based access)
  2. Witness role → blocked (403)
  3. Normal evidence scan → expected LOW/MEDIUM risk
  4. Admin review workflow (approve / flag)
  5. All-anomalies listing per role
  6. ML execution logs (admin only)
  7. Evidence hashes unchanged after scanning
  8. Graceful fallback reporting when model status is checked
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

def get_first_evidence_id(session):
    r = session.get(f"{BASE_URL}/api/evidence")
    if r.status_code == 200:
        data = r.json()
        items = data if isinstance(data, list) else data.get("evidence", [])
        if items:
            return items[0].get("evidence_id") or items[0].get("id")
    return None

# ─────────────────────────────────────────────
print("\n" + "="*60)
print("  ForensicChain ML Anomaly Detection Test Suite")
print("="*60)

# ── Test 1: ML Status Endpoint ──────────────────────────────
print("\n[1] ML Status Endpoint (role-based access)")

admin_s = make_session("admin")
if admin_s:
    r = admin_s.get(f"{BASE_URL}/api/ml/status")
    ok = r.status_code == 200
    check("Admin can access /api/ml/status", ok, f"HTTP {r.status_code}")
    if ok:
        d = r.json()
        check("Model reported as available", d.get("available") == True, str(d.get("available")))
        check("Model type is Isolation Forest", "Isolation" in d.get("model_type", ""), d.get("model_type"))
        check("Feature count is 12", d.get("feature_count") == 12, str(d.get("feature_count")))
        check("Disclaimer present", bool(d.get("disclaimer")), "")

analyst_s = make_session("analyst")
if analyst_s:
    r = analyst_s.get(f"{BASE_URL}/api/ml/status")
    check("Analyst can access /api/ml/status", r.status_code == 200, f"HTTP {r.status_code}")

court_s = make_session("court")
if court_s:
    r = court_s.get(f"{BASE_URL}/api/ml/status")
    check("Court can access /api/ml/status", r.status_code == 200, f"HTTP {r.status_code}")

police_s = make_session("police")
if police_s:
    r = police_s.get(f"{BASE_URL}/api/ml/status")
    # Police may have limited or no ML access based on role_required decorator
    check("Police ML status returns 200 or 403 (not 500)", r.status_code in (200, 403), f"HTTP {r.status_code}")

# ── Test 2: Witness Blocked ────────────────────────────────
print("\n[2] Witness Role — Must Be Blocked")
witness_s = make_session("witness")
if witness_s:
    r = witness_s.get(f"{BASE_URL}/api/ml/status")
    check("Witness blocked from /api/ml/status (403)", r.status_code == 403, f"HTTP {r.status_code}")

    # Also check anomalies endpoint
    r2 = witness_s.get(f"{BASE_URL}/api/ml/anomalies")
    check("Witness blocked from /api/ml/anomalies (403)", r2.status_code == 403, f"HTTP {r2.status_code}")

# ── Test 3: Normal Evidence Scan ───────────────────────────
print("\n[3] Normal Evidence Scan (Admin)")
evidence_id = None
original_hash = None
report_id = None

if admin_s:
    ev_id = get_first_evidence_id(admin_s)
    if ev_id:
        evidence_id = ev_id
        # Get original hash before scanning
        r_ev = admin_s.get(f"{BASE_URL}/api/evidence/{ev_id}")
        if r_ev.status_code == 200:
            ev_data = r_ev.json()
            ev_obj = ev_data.get("evidence") or ev_data
            original_hash = ev_obj.get("file_hash") or ev_obj.get("hash")

        r = admin_s.post(f"{BASE_URL}/api/ml/evidence/{ev_id}/analyze")
        ok = r.status_code == 200
        check(f"Admin can scan evidence {ev_id}", ok, f"HTTP {r.status_code}")
        if ok:
            d = r.json()
            check("Scan returns anomaly_score", "anomaly_score" in d, "")
            check("Scan returns risk_level", "risk_level" in d, "")
            check("Scan returns reasons list", isinstance(d.get("reasons"), list), "")
            check("Scan returns features dict", isinstance(d.get("features"), dict), "")
            check("Scan returns model_version", bool(d.get("model_version")), d.get("model_version"))
            check("Disclaimer in scan result", bool(d.get("disclaimer")), "")
            check("available=True in scan result", d.get("available") == True, "")
            risk = d.get("risk_level", "UNKNOWN")
            check(f"Risk level is LOW/MEDIUM/HIGH (not UNKNOWN)", risk in {"LOW","MEDIUM","HIGH"}, risk)
            report_id = d.get("report_id")
            check("Report ID returned", bool(report_id), str(report_id))
            print(f"      Score: {d.get('anomaly_score')}, Risk: {risk}, Report ID: {report_id}")
        else:
            print(f"      Response: {r.text[:200]}")
    else:
        print(f"  {SKIP} No evidence found — skipping scan test")

# ── Test 4: Evidence Hash Unchanged After Scan ─────────────
print("\n[4] Evidence Hash Integrity After Scan")
if admin_s and evidence_id and original_hash:
    r_ev2 = admin_s.get(f"{BASE_URL}/api/evidence/{evidence_id}")
    if r_ev2.status_code == 200:
        ev_data2 = r_ev2.json()
        ev_obj2 = ev_data2.get("evidence") or ev_data2
        new_hash = ev_obj2.get("file_hash") or ev_obj2.get("hash")
        check("Evidence hash unchanged after ML scan", original_hash == new_hash,
              f"{original_hash[:12]}... == {(new_hash or '')[:12]}...")
    else:
        print(f"  {SKIP} Could not re-fetch evidence")
elif not original_hash:
    print(f"  {SKIP} No original hash captured")

# ── Test 5: Analyst Can Scan ──────────────────────────────
print("\n[5] Analyst Evidence Scan")
if analyst_s and evidence_id:
    r = analyst_s.post(f"{BASE_URL}/api/ml/evidence/{evidence_id}/analyze")
    check("Analyst can scan evidence", r.status_code == 200, f"HTTP {r.status_code}")
    if r.status_code == 200:
        d = r.json()
        check("Analyst scan returns risk_level", bool(d.get("risk_level")), d.get("risk_level"))

# ── Test 6: Court Read-Only Scan ──────────────────────────
print("\n[6] Court Authority Evidence Scan (read-only)")
if court_s and evidence_id:
    r = court_s.post(f"{BASE_URL}/api/ml/evidence/{evidence_id}/analyze")
    # Court gets read-only access — 200 is acceptable; 403 if blocked by role
    check("Court scan returns 200 or 403 (not 500)", r.status_code in (200, 403), f"HTTP {r.status_code}")

# ── Test 7: Admin Review Workflow ─────────────────────────
print("\n[7] Admin Anomaly Review Workflow")
if admin_s and report_id:
    # Get all anomaly reports first
    r_list = admin_s.get(f"{BASE_URL}/api/ml/anomalies")
    ok_list = r_list.status_code == 200
    check("Admin can list anomaly reports", ok_list, f"HTTP {r_list.status_code}")
    if ok_list:
        reports = r_list.json()
        check("Anomaly report list is a list", isinstance(reports, list), str(type(reports)))

    # Review the scan we just created
    r_review = admin_s.post(
        f"{BASE_URL}/api/ml/reports/{report_id}/review",
        json={"review_status": "reviewed_benign", "review_notes": "Test review: normal behaviour confirmed"}
    )
    ok_review = r_review.status_code == 200
    check(f"Admin can review report #{report_id}", ok_review, f"HTTP {r_review.status_code}")
    if ok_review:
        rd = r_review.json()
        check("Review response contains report_id", "report_id" in rd, "")
        check("Review response contains review_status", rd.get("review_status") == "reviewed_benign", rd.get("review_status"))

    # Test invalid review status
    r_bad = admin_s.post(
        f"{BASE_URL}/api/ml/reports/{report_id}/review",
        json={"review_status": "invalid_status"}
    )
    check("Invalid review_status returns 400", r_bad.status_code == 400, f"HTTP {r_bad.status_code}")

    # Analyst cannot review
    if analyst_s:
        r_analyst_review = analyst_s.post(
            f"{BASE_URL}/api/ml/reports/{report_id}/review",
            json={"review_status": "reviewed_benign"}
        )
        check("Analyst cannot review reports (403)", r_analyst_review.status_code == 403, f"HTTP {r_analyst_review.status_code}")

else:
    print(f"  {SKIP} No report_id captured — skipping review test")

# ── Test 8: Role-Scoped Anomaly List ─────────────────────
print("\n[8] Role-Scoped Anomaly Reports List")
for role_name, sess in [("admin", admin_s), ("analyst", analyst_s), ("court", court_s)]:
    if sess:
        r = sess.get(f"{BASE_URL}/api/ml/anomalies")
        check(f"{role_name} can list anomalies", r.status_code == 200, f"HTTP {r.status_code}")

if witness_s:
    r = witness_s.get(f"{BASE_URL}/api/ml/anomalies")
    check("Witness blocked from anomaly list (403)", r.status_code == 403, f"HTTP {r.status_code}")

# ── Test 9: ML Logs (Admin Only) ──────────────────────────
print("\n[9] ML Execution Logs")
if admin_s:
    r = admin_s.get(f"{BASE_URL}/api/ml/logs")
    ok = r.status_code == 200
    check("Admin can access ML logs", ok, f"HTTP {r.status_code}")
    if ok:
        logs = r.json()
        check("ML logs is a list", isinstance(logs, list), "")
        if logs:
            check("Log entry has model_version", "model_version" in logs[0], "")
            check("Log entry has anomaly_score", "anomaly_score" in logs[0], "")

if analyst_s:
    r = analyst_s.get(f"{BASE_URL}/api/ml/logs")
    check("Analyst blocked from ML logs (403)", r.status_code == 403, f"HTTP {r.status_code}")

# ── Test 10: GET analyze endpoint ────────────────────────
print("\n[10] GET /api/ml/evidence/<id>/analyze (last report)")
if admin_s and evidence_id:
    r = admin_s.get(f"{BASE_URL}/api/ml/evidence/{evidence_id}/analyze")
    ok = r.status_code == 200
    check("GET analyze returns latest report", ok, f"HTTP {r.status_code}")
    if ok:
        d = r.json()
        check("GET analyze has risk_level", bool(d.get("risk_level")), d.get("risk_level"))

# ── Summary ──────────────────────────────────────────────
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
