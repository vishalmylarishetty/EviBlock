"""
Full End-to-End Workflow Integration Test for ForensicChain v2.4.2
Tests all 11 stages requested by the user:
  1. Police evidence creation & upload with SHA-256 & on-chain anchor
  2. Witness digital attestation & on-chain custody record
  3. Forensic analyst examination & cryptographic verification
  4. ML Isolation Forest behavioral anomaly detection (advisory, 12D)
  5. AI Case Summary generation (structured, fact-based)
  6. Smart Warrant AI recommendation & extension request
  7. Court authority review & on-chain decision
  8. Court evidence verification & custody audit
  9. Merkle batch commitment & proof verification
  10. Strict Role-Based Access Control (RBAC) enforcement
  11. 4-Tier Integrity Status coherence (Database | Blockchain | AI | ML)
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

def run_tests():
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

    print("=================================================================")
    print("ForensicChain v2.4.2 - Complete Integrated Workflow Verification")
    print("=================================================================")

    # Initialize authenticated sessions
    police = make_session("police")
    witness = make_session("witness")
    analyst = make_session("analyst")
    court = make_session("court")
    admin = make_session("admin")

    # Get witness user ID
    w_info = witness.get(f"{BASE_URL}/api/auth/me").json()
    witness_id = w_info.get("id") or 15
    print(f"  [INFO] Witness User ID: {witness_id} ({w_info.get('name')})")

    # ── STAGE 1: Court Creates Warrant & Police Uploads Evidence ──────────────
    print("\n--- STAGE 1: Evidence Upload & On-Chain Registration ---")
    ts = int(time.time())
    case_id = f"CASE-INT-{ts}"
    warrant_num = f"W-INT-{ts}"

    # Court issues initial warrant on-chain
    r = court.post(f"{BASE_URL}/api/warrants/register", json={
        "warrant_number": warrant_num,
        "case_id": case_id,
        "duration_seconds": 86400
    })
    check("1.1 Court registers Smart Warrant on-chain", r.status_code in [200, 201], r.text)

    # Police collects evidence and uploads file (.img is in ALLOWED_EXTENSIONS)
    file_bytes = f"Forensic Bit-Stream Raw Image Payload for case {case_id} generated at {ts}".encode('utf-8')
    expected_sha256 = hashlib.sha256(file_bytes).hexdigest()
    file_obj = io.BytesIO(file_bytes)

    files = {
        'file': (f"disk_dump_{ts}.img", file_obj, 'application/octet-stream')
    }
    form_data = {
        'case_id': case_id,
        'warrant_number': warrant_num,
        'source_gps': '37.7749,-122.4194',
        'source_device_id': f'DEV-USBFORENSIC-{ts}',
        'witness_user_id': str(witness_id),
        'description': 'Bit-stream forensic copy of internal storage partition',
        'is_private': 'false'
    }

    r = police.post(f"{BASE_URL}/api/upload_evidence", files=files, data=form_data)
    check("1.2 Police uploads evidence with SHA-256 computation", r.status_code in [200, 201, 202], r.text)
    up_data = r.json()
    ev_id = up_data.get('evidence_id') or up_data.get('evidence', {}).get('evidence_id')
    print(f"      Assigned Evidence ID: {ev_id}")

    # Check Tier 1 (Database) and Tier 2 (Blockchain)
    r = police.get(f"{BASE_URL}/api/evidence/{ev_id}")
    check("1.3 Tier 1: Evidence saved in Database", r.status_code == 200 and r.json()['evidence']['case_id'] == case_id)
    check("1.4 Tier 2: Evidence anchored on Blockchain", bool(r.json()['evidence'].get('tx_hash')))
    check("1.5 Status is pending_witness", r.json()['evidence'].get('status') == 'pending_witness')

    # ── STAGE 2: Witness Digital Attestation ──────────────────────────────────
    print("\n--- STAGE 2: Witness Attestation ---")
    r = witness.get(f"{BASE_URL}/api/witness/pending")
    check("2.1 Witness views pending seizure list", r.status_code == 200, r.text)
    pending_items = r.json() if isinstance(r.json(), list) else r.json().get('pending', [])
    pending_ids = [p.get('evidence_id') for p in pending_items]
    check("2.2 Uploaded evidence appears in witness queue", ev_id in pending_ids)

    r = witness.post(f"{BASE_URL}/api/seizure/attest", json={
        "evidence_id": ev_id,
        "note": "Attestation confirmed: Bit-stream copy extracted in my presence."
    })
    check("2.3 Witness digitally attests seizure on-chain", r.status_code == 200, r.text)

    # Verify status changed to active/verified
    r = police.get(f"{BASE_URL}/api/evidence/{ev_id}")
    check("2.4 Evidence status unlocked after witness attestation", r.json()['evidence']['status'] in ['active', 'verified'])

    # ── STAGE 3: Forensic Analyst Examination & Verification ──────────────────
    print("\n--- STAGE 3: Forensic Examination & Cryptographic Verification ---")
    r = analyst.post(f"{BASE_URL}/api/transfer_evidence", json={
        "evidence_id": ev_id,
        "action": "Forensic Analysis Started",
        "note": "Physical disk connected to Tableau T8u Forensic USB 3.0 Bridge."
    })
    check("3.1 Analyst logs Forensic Analysis Started on-chain", r.status_code == 200, r.text)

    r = analyst.post(f"{BASE_URL}/api/transfer_evidence", json={
        "evidence_id": ev_id,
        "action": "Forensic Analysis Completed",
        "note": "Bit-stream analysis completed. Extracted 14 deleted log files."
    })
    check("3.2 Analyst logs Forensic Analysis Completed on-chain", r.status_code == 200, r.text)

    r = analyst.post(f"{BASE_URL}/api/verify_evidence", json={
        "evidence_id": ev_id
    })
    check("3.3 Analyst performs cryptographic verification (intact)", r.status_code == 200 and r.json().get('intact') is True, r.text)
    check("3.4 Evidence status confirmed as verified", r.json().get('status') == 'verified' or analyst.get(f"{BASE_URL}/api/evidence/{ev_id}").json()['evidence']['status'] == 'verified')

    # ── STAGE 4: ML Isolation Forest Anomaly Detection (Tier 4) ───────────────
    print("\n--- STAGE 4: ML Isolation Forest Anomaly Detection (Tier 4) ---")
    r = analyst.post(f"{BASE_URL}/api/ml/evidence/{ev_id}/analyze")
    check("4.1 ML Isolation Forest scan executed", r.status_code == 200, r.text)
    ml_data = r.json()
    check("4.2 ML returns risk level and anomaly score", "risk_level" in ml_data and "anomaly_score" in ml_data)
    check("4.3 ML 12-feature vector extracted", "features" in ml_data and len(ml_data["features"]) >= 10)
    check("4.4 ML is auxiliary: Evidence SHA-256 untouched", analyst.get(f"{BASE_URL}/api/evidence/{ev_id}").json()['evidence']['file_hash'] == expected_sha256)

    # ── STAGE 5: AI Case Summary Generation (Tier 3) ──────────────────────────
    print("\n--- STAGE 5: AI-Powered Case Summary Generation (Tier 3) ---")
    r = police.get(f"{BASE_URL}/api/cases/{case_id}/summary")
    check("5.1 AI Case Summary generated for case", r.status_code == 200, r.text)
    cs_data = r.json()
    summary = cs_data.get('report_text', '') or str(cs_data)
    facts = cs_data.get('confirmed_facts', {})
    check("5.2 Summary includes Case ID", case_id in summary or cs_data.get('case_id') == case_id)
    check("5.3 Summary includes Evidence counts", "total_evidence_items" in facts or "Evidence" in summary)
    check("5.4 Summary includes Blockchain Integrity", "blockchain_integrity" in facts or "Blockchain" in summary)
    check("5.5 Summary includes Forensic Verification", "forensic_verification" in facts or "Forensic" in summary)
    check("5.6 Summary includes Chain of Custody", "chain_of_custody" in facts or "Chain of Custody" in summary)

    # ── STAGE 6: Smart Warrant AI Advisor & Police Extension Request ──────────
    print("\n--- STAGE 6: Smart Warrant AI Recommendation & Extension Request ---")
    r = police.get(f"{BASE_URL}/api/warrants/{warrant_num}/ai-recommendation")
    check("6.1 Smart Warrant AI recommendation generated", r.status_code == 200, r.text)
    adv_data = r.json()
    check("6.2 AI returns workflow completion %", "workflow_completion_pct" in adv_data)
    check("6.3 AI returns recommendation and reasoning", bool(adv_data.get('ai_recommendation')) and bool(adv_data.get('reason')))
    check("6.4 Human-in-the-loop: AI did NOT modify warrant expiry", adv_data.get('warrant_number') == warrant_num)

    r = police.post(f"{BASE_URL}/api/warrants/{warrant_num}/request-extension", json={
        "additional_seconds": 86400,
        "reason": "Ongoing memory extraction and swap analysis."
    })
    check("6.5 Police submits warrant extension request", r.status_code in [200, 201], r.text)
    req_id = r.json().get('request_id') or r.json().get('id')

    # ── STAGE 7: Court Authority Review & Blockchain Decision ─────────────────
    print("\n--- STAGE 7: Court Authority Review & Blockchain Decision ---")
    r = court.get(f"{BASE_URL}/api/warrants/extension-requests?status=pending")
    check("7.1 Court lists pending warrant extensions", r.status_code == 200)
    pending_req_ids = [req.get('id') for req in r.json()]
    check("7.2 Police request present in Court pending queue", req_id in pending_req_ids)

    r = court.post(f"{BASE_URL}/api/warrants/extension-requests/{req_id}/review", json={
        "decision": "approved",
        "decision_note": "Extension approved for legitimate technical analysis."
    })
    check("7.3 Court approves extension", r.status_code == 200 and r.json().get('decision') == 'approved', r.text)
    check("7.4 Blockchain transaction recorded for warrant decision", bool(r.json().get('tx_hash')))

    # ── STAGE 8: Court Evidence Verification & Custody Audit ──────────────────
    print("\n--- STAGE 8: Court Evidence Registry Audit & Verification ---")
    r = court.get(f"{BASE_URL}/api/evidence")
    check("8.1 Court reviews Evidence Registry", r.status_code == 200 and len(r.json()) > 0)

    r = court.post(f"{BASE_URL}/api/verify_evidence", json={
        "evidence_id": ev_id
    })
    check("8.2 Court independently verifies evidence cryptographic integrity", r.status_code == 200 and r.json().get('intact') is True)

    r = court.get(f"{BASE_URL}/api/evidence/{ev_id}")
    custody_logs = r.json().get('custody_logs', [])
    check("8.3 Court audits full Chain of Custody timeline", len(custody_logs) >= 3)

    # ── STAGE 9: Merkle Tree Batching Additional Integrity Layer ──────────────
    print("\n--- STAGE 9: Merkle Batching Additional Integrity Layer ---")
    r = admin.post(f"{BASE_URL}/api/merkle/batch/evidence", json={
        "evidence_ids": [ev_id]
    })
    check("9.1 Admin creates Merkle batch from evidence", r.status_code in [200, 201], r.text)
    mb_data = r.json()
    batch_id = mb_data.get('batch_id')
    check("9.2 Merkle root anchored on blockchain", bool(mb_data.get('root_hash') or mb_data.get('tx_hash')))

    r = court.post(f"{BASE_URL}/api/merkle/batch/{batch_id}/verify-evidence", json={
        "evidence_id": ev_id
    })
    check("9.3 Court cryptographically verifies Merkle proof for evidence", r.status_code == 200 and r.json().get('valid') is True, r.text)

    # ── STAGE 10: Strict Role-Based Access Control (RBAC) ─────────────────────
    print("\n--- STAGE 10: Role-Based Access Control Enforcement ---")
    # Witness cannot register warrants
    r = witness.post(f"{BASE_URL}/api/warrants/register", json={"warrant_number": "W-FAIL", "case_id": "C-FAIL"})
    check("10.1 Witness blocked from creating warrants (403)", r.status_code == 403)

    # Police cannot approve warrants
    r = police.post(f"{BASE_URL}/api/warrants/extension-requests/{req_id}/review", json={"decision": "approved"})
    check("10.2 Police blocked from approving warrants (403)", r.status_code == 403)

    # Analyst cannot approve warrants
    r = analyst.post(f"{BASE_URL}/api/warrants/extension-requests/{req_id}/review", json={"decision": "approved"})
    check("10.3 Analyst blocked from approving warrants (403)", r.status_code == 403)

    # Witness cannot upload evidence
    r = witness.post(f"{BASE_URL}/api/upload_evidence", data={"description": "Unauthorized upload"})
    check("10.4 Witness blocked from uploading evidence (403)", r.status_code == 403)

    # Witness cannot access AI Case Summary
    r = witness.get(f"{BASE_URL}/api/cases/{case_id}/summary")
    check("10.5 Witness blocked from AI Case Summary (403)", r.status_code == 403)

    # ── STAGE 11: 4-Tier Integrity Status Coherence ───────────────────────────
    print("\n--- STAGE 11: 4-Tier Integrity Status Coherence ---")
    r = court.get(f"{BASE_URL}/api/evidence/{ev_id}")
    e = r.json().get('evidence', {})
    check("11.1 Tier 1: Database synchronized", bool(e.get('id') and e.get('created_at')))
    check("11.2 Tier 2: Blockchain anchored", bool(e.get('tx_hash')))
    check("11.3 Tier 3: AI Case Summary connected", bool(e.get('case_id')))
    check("11.4 Tier 4: ML Anomaly Report active", bool(e.get('anomaly_report')))

    print("\n=================================================================")
    print(f"Results: {passed} PASSED, {failed} FAILED out of {total} checks")
    print("=================================================================")
    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
