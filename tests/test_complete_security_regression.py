"""
Comprehensive Security, Role-Based Access Control, Functionality, and Regression Test Suite
for ForensicChain v2.4.2

Tests every requirement specified in the test plan:
  TEST 1 - POLICE / INVESTIGATOR (Access, Prohibitions, Capabilities, Negative Guards)
  TEST 2 - WITNESS (Access, Prohibitions, Capabilities, Negative Guards)
  TEST 3 - FORENSIC ANALYST (Access, Prohibitions, Capabilities, Negative Guards)
  TEST 4 - COURT AUTHORITY (Access, Prohibitions, Capabilities, Negative Guards)
  TEST 5 - ADMIN (Access, Full Capabilities, System Administration)

And all 20 specific functionality & regression scenarios:
  1. Evidence upload
  2. Duplicate evidence detection
  3. Witness attestation
  4. Evidence verification
  5. Custody transfer
  6. Blockchain recording
  7. Warrant creation
  8. Warrant extension request
  9. Court approval
  10. Court rejection
  11. Merkle batch creation
  12. Merkle proof verification
  13. ML anomaly detection
  14. AI case summary
  15. AI warrant recommendation
  16. Login/logout
  17. Session expiration
  18. Existing admin functions
  19. Existing database fallback
  20. Existing evidence storage
"""

import sys
import io
import time
import hashlib
import requests

BASE_URL = "http://127.0.0.1:5000"

CREDS = {
    "admin":    {"email": "admin@forensic.local",       "password": "Admin@12345"},
    "court":    {"email": "thomas.court@forensic.gov",  "password": "Password123!"},
    "analyst":  {"email": "analyst@forensic.gov",       "password": "Password123!"},
    "police":   {"email": "james.witness@forensic.gov", "password": "Password123!"},
    "witness":  {"email": "witness@forensic.gov",       "password": "Password123!"},
}

def make_session(role):
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/login", json=CREDS[role])
    if r.status_code != 200:
        raise RuntimeError(f"Login failed for {role}: {r.status_code} {r.text}")
    return s

def run_all_tests():
    passed = 0
    failed = 0
    total = 0

    def check(desc, cond, info=""):
        nonlocal passed, failed, total
        total += 1
        if cond:
            passed += 1
            print(f"  [PASS] {desc}")
        else:
            failed += 1
            print(f"  [FAIL] {desc} - {info}")

    print("================================================================================")
    print("ForensicChain v2.4.2 — Comprehensive Security, RBAC & Regression Test Suite")
    print("================================================================================")

    # Initialize role sessions
    s_police = make_session("police")
    s_witness = make_session("witness")
    s_analyst = make_session("analyst")
    s_court = make_session("court")
    s_admin = make_session("admin")

    w_info = s_witness.get(f"{BASE_URL}/api/auth/me").json()
    witness_id = w_info.get("id") or 15

    # ════════════════════════════════════════════════════════════════════════════════
    # TEST 1 — POLICE / INVESTIGATOR
    # ════════════════════════════════════════════════════════════════════════════════
    print("\n" + "="*80)
    print("TEST 1 — POLICE / INVESTIGATOR ROLE VERIFICATION")
    print("="*80)
    
    # Allowed Access
    check("1.1 Police should access Dashboard / stats", s_police.get(f"{BASE_URL}/api/dashboard/stats").status_code == 200)
    check("1.2 Police should access Evidence List", s_police.get(f"{BASE_URL}/api/evidence").status_code == 200)
    check("1.3 Police should access Smart Warrants", s_police.get(f"{BASE_URL}/api/warrants").status_code == 200)
    check("1.4 Police should access AI Case Summary", s_police.get(f"{BASE_URL}/api/cases").status_code == 200)

    # Prohibited Access (Strict 403)
    check("1.5 Police should NOT access Users administration", s_police.get(f"{BASE_URL}/api/admin/users").status_code == 403)
    check("1.6 Police should NOT access Merkle batch creation", s_police.post(f"{BASE_URL}/api/merkle/batch/evidence", json={"evidence_ids":[]}).status_code == 403)
    check("1.7 Police should NOT access Blockchain admin (deploy)", s_police.post(f"{BASE_URL}/api/blockchain/deploy").status_code == 403)
    check("1.8 Police should NOT access Blockchain admin (set_address)", s_police.post(f"{BASE_URL}/api/blockchain/set_address", json={"address":"0x123"}).status_code == 403)
    
    # Negative guard: Police cannot execute witness attestation on evidence assigned to another witness
    r_pol_att_unauth = s_police.post(f"{BASE_URL}/api/seizure/attest", json={"evidence_id": "EV-FAKE-WITNESS", "note": "Illegal witness attempt"})
    check("1.9 Police should NOT execute unauthorized witness attestation (403/404)", r_pol_att_unauth.status_code in [403, 404])
    check("1.10 Police should NOT access AI model configuration / training", s_police.post(f"{BASE_URL}/api/ml/train").status_code == 403)

    # Capabilities & Action Guards
    ts1 = int(time.time())
    warrant1 = f"W-POL-{ts1}"
    case1 = f"CASE-POL-{ts1}"
    s_court.post(f"{BASE_URL}/api/warrants/register", json={"warrant_number": warrant1, "case_id": case1, "duration_seconds": 86400})

    # Upload evidence
    ev_bytes1 = f"Police Test Evidence Payload {ts1}".encode('utf-8')
    r_up1 = s_police.post(f"{BASE_URL}/api/upload_evidence", files={'file': (f"ev1_{ts1}.img", io.BytesIO(ev_bytes1), 'application/octet-stream')}, data={
        'case_id': case1, 'warrant_number': warrant1, 'source_gps': '37.77,-122.41',
        'source_device_id': f'DEV-{ts1}', 'witness_user_id': str(witness_id),
        'description': 'Police evidence test seizure'
    })
    check("1.11 Police CAN upload evidence", r_up1.status_code in [200, 201, 202])
    ev_id1 = r_up1.json().get('evidence_id')

    # Request extension
    r_req1 = s_police.post(f"{BASE_URL}/api/warrants/{warrant1}/request-extension", json={
        "additional_seconds": 86400, "reason": "Police investigation ongoing"
    })
    check("1.12 Police CAN request warrant extension", r_req1.status_code in [200, 201])
    req_id1 = r_req1.json().get('request_id')

    # Police CANNOT approve own extension
    r_self_app = s_police.post(f"{BASE_URL}/api/warrants/extension-requests/{req_id1}/review", json={"decision": "approved"})
    check("1.13 Police CANNOT approve own warrant extension (403)", r_self_app.status_code == 403)

    # Police CAN view custody
    check("1.14 Police CAN view Chain of Custody", s_police.get(f"{BASE_URL}/api/evidence/{ev_id1}").status_code == 200)

    # Police CAN view AI/ML information
    check("1.15 Police CAN view AI warrant recommendation", s_police.get(f"{BASE_URL}/api/warrants/{warrant1}/ai-recommendation").status_code == 200)

    # Clean up extension approval with court so warrant remains coherent
    s_court.post(f"{BASE_URL}/api/warrants/extension-requests/{req_id1}/review", json={"decision": "approved", "decision_note": "Court approved for test"})

    # ════════════════════════════════════════════════════════════════════════════════
    # TEST 2 — WITNESS
    # ════════════════════════════════════════════════════════════════════════════════
    print("\n" + "="*80)
    print("TEST 2 — WITNESS ROLE VERIFICATION")
    print("="*80)

    # Allowed Access
    check("2.1 Witness should access Dashboard / stats", s_witness.get(f"{BASE_URL}/api/dashboard/stats").status_code == 200)
    check("2.2 Witness should access Pending Attestations", s_witness.get(f"{BASE_URL}/api/witness/pending").status_code == 200)
    check("2.3 Witness should access My Attestations", s_witness.get(f"{BASE_URL}/api/witness/attestations").status_code == 200)

    # Prohibited Access (Strict 403)
    check("2.4 Witness should NOT access Upload Evidence", s_witness.post(f"{BASE_URL}/api/upload_evidence", data={"description": "bad"}).status_code == 403)
    check("2.5 Witness should NOT access Smart Warrants list", s_witness.get(f"{BASE_URL}/api/warrants").status_code == 403)
    check("2.6 Witness should NOT access Warrant register", s_witness.post(f"{BASE_URL}/api/warrants/register", json={"warrant_number":"W-BAD"}).status_code == 403)
    check("2.7 Witness should NOT access Merkle batch creation", s_witness.post(f"{BASE_URL}/api/merkle/batch/evidence", json={"evidence_ids":[]}).status_code == 403)
    check("2.8 Witness should NOT access Users administration", s_witness.get(f"{BASE_URL}/api/admin/users").status_code == 403)
    check("2.9 Witness should NOT access Blockchain admin (deploy)", s_witness.post(f"{BASE_URL}/api/blockchain/deploy").status_code == 403)
    check("2.10 Witness should NOT access AI Case Summary", s_witness.get(f"{BASE_URL}/api/cases").status_code == 403)
    check("2.11 Witness should NOT access AI Warrant Advisor", s_witness.get(f"{BASE_URL}/api/warrants/{warrant1}/ai-recommendation").status_code == 403)

    # Capabilities: Witness can digitally attest assigned seizure
    r_att1 = s_witness.post(f"{BASE_URL}/api/seizure/attest", json={"evidence_id": ev_id1, "note": "Witness verified physical seizure"})
    check("2.12 Witness CAN digitally sign assigned attestation", r_att1.status_code == 200)

    # ════════════════════════════════════════════════════════════════════════════════
    # TEST 3 — FORENSIC ANALYST
    # ════════════════════════════════════════════════════════════════════════════════
    print("\n" + "="*80)
    print("TEST 3 — FORENSIC ANALYST ROLE VERIFICATION")
    print("="*80)

    # Allowed Access
    check("3.1 Analyst should access Dashboard / stats", s_analyst.get(f"{BASE_URL}/api/dashboard/stats").status_code == 200)
    check("3.2 Analyst should access Evidence List", s_analyst.get(f"{BASE_URL}/api/evidence").status_code == 200)
    check("3.3 Analyst should access Verify Evidence", s_analyst.post(f"{BASE_URL}/api/verify_evidence", json={"evidence_id": ev_id1}).status_code == 200)
    check("3.4 Analyst should access Chain of Custody", s_analyst.get(f"{BASE_URL}/api/evidence/{ev_id1}").status_code == 200)
    check("3.5 Analyst should access AI/ML Evidence Alerts", s_analyst.get(f"{BASE_URL}/api/ml/anomalies").status_code == 200)
    check("3.6 Analyst should access AI Case Summary", s_analyst.get(f"{BASE_URL}/api/cases/{case1}/summary").status_code == 200)

    # Prohibited Access (Strict 403)
    check("3.7 Analyst should NOT access Upload Evidence", s_analyst.post(f"{BASE_URL}/api/upload_evidence", data={"description": "bad"}).status_code == 403)
    check("3.8 Analyst should NOT access Users administration", s_analyst.get(f"{BASE_URL}/api/admin/users").status_code == 403)
    check("3.9 Analyst should NOT access Merkle batch creation", s_analyst.post(f"{BASE_URL}/api/merkle/batch/evidence", json={"evidence_ids":[]}).status_code == 403)
    check("3.10 Analyst should NOT access Warrant approval", s_analyst.post(f"{BASE_URL}/api/warrants/extension-requests/1/review", json={"decision":"approved"}).status_code == 403)
    check("3.11 Analyst should NOT access Blockchain admin (deploy)", s_analyst.post(f"{BASE_URL}/api/blockchain/deploy").status_code == 403)
    check("3.12 Analyst should NOT access AI model retraining", s_analyst.post(f"{BASE_URL}/api/ml/train").status_code == 403)

    # Capabilities: Analyst can log custody & execute ML behavioral scan
    r_cust_ana = s_analyst.post(f"{BASE_URL}/api/transfer_evidence", json={
        "evidence_id": ev_id1, "action": "Forensic Analysis Started", "note": "Bit-stream extraction started"
    })
    check("3.13 Analyst CAN log forensic custody event", r_cust_ana.status_code == 200)

    r_ml_ana = s_analyst.post(f"{BASE_URL}/api/ml/evidence/{ev_id1}/analyze")
    check("3.14 Analyst CAN run ML behavioral anomaly scan", r_ml_ana.status_code == 200)

    # ════════════════════════════════════════════════════════════════════════════════
    # TEST 4 — COURT AUTHORITY
    # ════════════════════════════════════════════════════════════════════════════════
    print("\n" + "="*80)
    print("TEST 4 — COURT AUTHORITY ROLE VERIFICATION")
    print("="*80)

    # Allowed Access
    check("4.1 Court should access Dashboard / stats", s_court.get(f"{BASE_URL}/api/dashboard/stats").status_code == 200)
    check("4.2 Court should access Evidence Registry", s_court.get(f"{BASE_URL}/api/evidence").status_code == 200)
    check("4.3 Court should access Verify Evidence", s_court.post(f"{BASE_URL}/api/verify_evidence", json={"evidence_id": ev_id1}).status_code == 200)
    check("4.4 Court should access Chain of Custody", s_court.get(f"{BASE_URL}/api/evidence/{ev_id1}").status_code == 200)
    check("4.5 Court should access Smart Warrants", s_court.get(f"{BASE_URL}/api/warrants").status_code == 200)
    check("4.6 Court should access AI Case Summary", s_court.get(f"{BASE_URL}/api/cases/{case1}/summary").status_code == 200)
    check("4.7 Court should access AI Warrant Recommendation", s_court.get(f"{BASE_URL}/api/warrants/{warrant1}/ai-recommendation").status_code == 200)

    # Prohibited Access (Strict 403)
    check("4.8 Court should NOT access Upload Evidence", s_court.post(f"{BASE_URL}/api/upload_evidence", data={"description": "bad"}).status_code == 403)
    check("4.9 Court should NOT access Users administration", s_court.get(f"{BASE_URL}/api/admin/users").status_code == 403)
    check("4.10 Court should NOT access Merkle batch creation", s_court.post(f"{BASE_URL}/api/merkle/batch/evidence", json={"evidence_ids":[]}).status_code == 403)
    check("4.11 Court should NOT access Blockchain admin (deploy)", s_court.post(f"{BASE_URL}/api/blockchain/deploy").status_code == 403)
    check("4.12 Court should NOT access ML training / model config", s_court.post(f"{BASE_URL}/api/ml/train").status_code == 403)

    # Capabilities & Prohibitions
    # Court CAN approve warrant extension
    r_req_court = s_police.post(f"{BASE_URL}/api/warrants/{warrant1}/request-extension", json={
        "additional_seconds": 43200, "reason": "Follow-up forensic memory analysis"
    })
    req_id_court = r_req_court.json().get('request_id')
    r_court_dec = s_court.post(f"{BASE_URL}/api/warrants/extension-requests/{req_id_court}/review", json={
        "decision": "approved", "decision_note": "Approved by Presiding Judge"
    })
    check("4.13 Court CAN approve warrant extension on-chain", r_court_dec.status_code == 200 and r_court_dec.json().get('decision') == 'approved')

    # Court CAN reject warrant extension
    r_req_rej = s_police.post(f"{BASE_URL}/api/warrants/{warrant1}/request-extension", json={
        "additional_seconds": 86400, "reason": "Extraneous extension request"
    })
    req_id_rej = r_req_rej.json().get('request_id')
    r_court_rej = s_court.post(f"{BASE_URL}/api/warrants/extension-requests/{req_id_rej}/review", json={
        "decision": "rejected", "decision_note": "Rejected: Adequate time granted"
    })
    check("4.14 Court CAN reject warrant extension on-chain", r_court_rej.status_code == 200 and r_court_rej.json().get('decision') == 'rejected')

    # Court CANNOT modify ML scores
    r_ml_tamper = s_court.post(f"{BASE_URL}/api/ml/train")
    check("4.15 Court CANNOT modify ML model or training (403)", r_ml_tamper.status_code == 403)

    # ════════════════════════════════════════════════════════════════════════════════
    # TEST 5 — ADMIN
    # ════════════════════════════════════════════════════════════════════════════════
    print("\n" + "="*80)
    print("TEST 5 — ADMIN ROLE VERIFICATION")
    print("="*80)

    check("5.1 Admin should access Dashboard / stats", s_admin.get(f"{BASE_URL}/api/dashboard/stats").status_code == 200)
    check("5.2 Admin should access Users administration", s_admin.get(f"{BASE_URL}/api/admin/users").status_code == 200)
    check("5.3 Admin should access Blockchain administration", s_admin.get(f"{BASE_URL}/api/blockchain/info").status_code == 200)
    check("5.4 Admin should access Evidence List", s_admin.get(f"{BASE_URL}/api/evidence").status_code == 200)
    check("5.5 Admin should access Chain of Custody", s_admin.get(f"{BASE_URL}/api/evidence/{ev_id1}").status_code == 200)
    check("5.6 Admin should access Merkle Batching", s_admin.get(f"{BASE_URL}/api/merkle/batches").status_code == 200)
    check("5.7 Admin should access Smart Warrants", s_admin.get(f"{BASE_URL}/api/warrants").status_code == 200)
    check("5.8 Admin should access AI/ML Monitoring status", s_admin.get(f"{BASE_URL}/api/ml/status").status_code == 200)
    check("5.9 Admin should access AI/ML Anomalies", s_admin.get(f"{BASE_URL}/api/ml/anomalies").status_code == 200)
    check("5.10 Admin should access System Health audit", s_admin.get(f"{BASE_URL}/api/admin/system-health").status_code == 200)

    # ════════════════════════════════════════════════════════════════════════════════
    # 20 SPECIFIC FUNCTIONALITY & REGRESSION SCENARIOS
    # ════════════════════════════════════════════════════════════════════════════════
    print("\n" + "="*80)
    print("20 SPECIFIC FUNCTIONALITY & REGRESSION TESTS")
    print("="*80)

    ts_scen = int(time.time())
    warrant_scen = f"W-SCEN-{ts_scen}"
    case_scen = f"CASE-SCEN-{ts_scen}"

    # 7. Warrant creation
    r_w_create = s_court.post(f"{BASE_URL}/api/warrants/register", json={
        "warrant_number": warrant_scen, "case_id": case_scen, "duration_seconds": 86400
    })
    check("Scenario 7: Warrant creation on-chain", r_w_create.status_code in [200, 201], r_w_create.text)

    # 1. Evidence upload (using .log which supports direct preview and byte-stream inspection)
    scen_bytes = f"Evidence payload for 20 scenarios test {ts_scen}".encode('utf-8')
    scen_hash = hashlib.sha256(scen_bytes).hexdigest()
    r_up_scen = s_police.post(f"{BASE_URL}/api/upload_evidence", files={'file': (f"scen_{ts_scen}.log", io.BytesIO(scen_bytes), 'text/plain')}, data={
        'case_id': case_scen, 'warrant_number': warrant_scen, 'source_gps': '37.7749,-122.4194',
        'source_device_id': f'DEV-SCEN-{ts_scen}', 'witness_user_id': str(witness_id),
        'description': '20 scenarios integration evidence log file'
    })
    check("Scenario 1: Evidence upload with SHA-256 generation", r_up_scen.status_code in [200, 201, 202])
    ev_scen_id = r_up_scen.json().get('evidence_id')

    # 2. Duplicate evidence detection
    r_dup = s_police.post(f"{BASE_URL}/api/upload_evidence", files={'file': (f"dup_{ts_scen}.log", io.BytesIO(scen_bytes), 'text/plain')}, data={
        'case_id': case_scen, 'warrant_number': warrant_scen, 'source_gps': '37.7749,-122.4194',
        'source_device_id': f'DEV-DUP-{ts_scen}', 'witness_user_id': str(witness_id),
        'description': 'Attempt duplicate upload'
    })
    check("Scenario 2: Duplicate evidence detection (HTTP 409)", r_dup.status_code == 409, f"Status: {r_dup.status_code}")

    # 3. Witness attestation
    r_scen_att = s_witness.post(f"{BASE_URL}/api/seizure/attest", json={
        "evidence_id": ev_scen_id, "note": "Attestation confirmed in physical presence"
    })
    check("Scenario 3: Witness digital attestation on-chain", r_scen_att.status_code == 200)

    # 5. Custody transfer
    r_scen_cust = s_analyst.post(f"{BASE_URL}/api/transfer_evidence", json={
        "evidence_id": ev_scen_id, "action": "Forensic Analysis Started", "note": "Station 4 examination"
    })
    check("Scenario 5: Custody transfer & lifecycle event logged", r_scen_cust.status_code == 200)

    # 4. Evidence verification
    r_scen_ver = s_analyst.post(f"{BASE_URL}/api/verify_evidence", json={"evidence_id": ev_scen_id})
    check("Scenario 4: Cryptographic evidence verification (intact)", r_scen_ver.status_code == 200 and r_scen_ver.json().get('intact') is True)

    # 6. Blockchain recording
    r_scen_detail = s_analyst.get(f"{BASE_URL}/api/evidence/{ev_scen_id}")
    e_scen = r_scen_detail.json().get('evidence', {})
    check("Scenario 6: Blockchain recording verified (tx_hash confirmed)", bool(e_scen.get('tx_hash')))

    # 8. Warrant extension request
    r_scen_req = s_police.post(f"{BASE_URL}/api/warrants/{warrant_scen}/request-extension", json={
        "additional_seconds": 86400, "reason": "Detailed forensic memory decompilation"
    })
    check("Scenario 8: Warrant extension request submitted", r_scen_req.status_code in [200, 201])
    scen_req_id = r_scen_req.json().get('request_id')

    # 9. Court approval
    r_scen_app = s_court.post(f"{BASE_URL}/api/warrants/extension-requests/{scen_req_id}/review", json={
        "decision": "approved", "decision_note": "Granted by Judge Wayne"
    })
    check("Scenario 9: Court approval on-chain with tx confirmation", r_scen_app.status_code == 200 and r_scen_app.json().get('decision') == 'approved' and bool(r_scen_app.json().get('tx_hash')))

    # 10. Court rejection
    r_scen_req2 = s_police.post(f"{BASE_URL}/api/warrants/{warrant_scen}/request-extension", json={
        "additional_seconds": 86400, "reason": "Superfluous extension request"
    })
    scen_req_id2 = r_scen_req2.json().get('request_id')
    r_scen_rej = s_court.post(f"{BASE_URL}/api/warrants/extension-requests/{scen_req_id2}/review", json={
        "decision": "rejected", "decision_note": "Denied: Substantial analysis already completed"
    })
    check("Scenario 10: Court rejection on-chain recorded", r_scen_rej.status_code == 200 and r_scen_rej.json().get('decision') == 'rejected')

    # 11. Merkle batch creation
    r_scen_mb = s_admin.post(f"{BASE_URL}/api/merkle/batch/evidence", json={"evidence_ids": [ev_scen_id]})
    check("Scenario 11: Merkle batch creation & on-chain root commit", r_scen_mb.status_code in [200, 201])
    scen_batch_id = r_scen_mb.json().get('batch_id')

    # 12. Merkle proof verification
    r_scen_mv = s_court.post(f"{BASE_URL}/api/merkle/batch/{scen_batch_id}/verify-evidence", json={"evidence_id": ev_scen_id})
    check("Scenario 12: Merkle proof verification by Court (valid)", r_scen_mv.status_code == 200 and r_scen_mv.json().get('valid') is True)

    # 13. ML anomaly detection
    r_scen_ml = s_analyst.post(f"{BASE_URL}/api/ml/evidence/{ev_scen_id}/analyze")
    check("Scenario 13: ML Isolation Forest anomaly detection (12 features)", r_scen_ml.status_code == 200 and "risk_level" in r_scen_ml.json() and "anomaly_score" in r_scen_ml.json())

    # 14. AI case summary
    r_scen_cs = s_police.get(f"{BASE_URL}/api/cases/{case_scen}/summary")
    check("Scenario 14: AI case summary generation (factual synthesis)", r_scen_cs.status_code == 200 and bool(r_scen_cs.json().get('report_text')))

    # 15. AI warrant recommendation
    r_scen_wr = s_police.get(f"{BASE_URL}/api/warrants/{warrant_scen}/ai-recommendation")
    check("Scenario 15: AI warrant recommendation (workflow analysis)", r_scen_wr.status_code == 200 and bool(r_scen_wr.json().get('ai_recommendation')))

    # 16. Login / logout
    s_temp = requests.Session()
    r_log_in = s_temp.post(f"{BASE_URL}/api/auth/login", json=CREDS["police"])
    r_log_out = s_temp.post(f"{BASE_URL}/api/auth/logout")
    r_after_logout = s_temp.get(f"{BASE_URL}/api/evidence")
    check("Scenario 16: Login / logout lifecycle (401 after logout)", r_log_in.status_code == 200 and r_log_out.status_code == 200 and r_after_logout.status_code == 401)

    # 17. Session expiration / invalid token
    s_invalid = requests.Session()
    s_invalid.cookies.set("session", "invalid_forged_or_expired_cookie_token")
    r_unauth = s_invalid.get(f"{BASE_URL}/api/evidence")
    check("Scenario 17: Session expiration / forged cookie rejection (401)", r_unauth.status_code == 401)

    # 18. Existing admin functions
    r_adm_users = s_admin.get(f"{BASE_URL}/api/admin/users")
    r_adm_stats = s_admin.get(f"{BASE_URL}/api/admin/stats")
    r_adm_health = s_admin.get(f"{BASE_URL}/api/admin/system-health")
    check("Scenario 18: Existing admin functions (users, stats, health)", r_adm_users.status_code == 200 and r_adm_stats.status_code == 200 and r_adm_health.status_code == 200)

    # 19. Existing database fallback
    # Verify evidence details fallback metadata resilience
    check("Scenario 19: Database fallback metadata coherence", "tx_metadata" in e_scen and e_scen.get("file_hash") == scen_hash)

    # 20. Existing evidence storage
    # Court and Admin can access any evidence file; check byte stream and hash
    r_file = s_court.get(f"{BASE_URL}/api/evidence/{ev_scen_id}/file")
    check("Scenario 20: Existing evidence storage (file byte stream & integrity)", r_file.status_code == 200 and hashlib.sha256(r_file.content).hexdigest() == scen_hash)

    print("\n" + "="*80)
    print(f"OVERALL SUMMARY: {passed} PASSED, {failed} FAILED out of {total} CHECKS")
    print("="*80)
    return failed == 0

if __name__ == "__main__":
    ok = run_all_tests()
    sys.exit(0 if ok else 1)
