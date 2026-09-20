import requests
import time

BASE = 'http://127.0.0.1:5000'

def login(email, password):
    s = requests.Session()
    r = s.post(f'{BASE}/api/auth/login', json={'email': email, 'password': password})
    assert r.status_code == 200, f"Login failed for {email}: {r.text}"
    return s

print("=== Starting Smart Warrants Two-Party Workflow Verification ===")

# 1. Login required roles
s_police = login('james.witness@forensic.gov', 'Password123!')
s_court = login('thomas.court@forensic.gov', 'Password123!')
s_witness = login('witness@forensic.gov', 'Password123!')
s_analyst = login('analyst@forensic.gov', 'Password123!')

warrant_num = f"WR-TEST-{int(time.time())}"
case_id = "CASE-WARRANT-AUDIT-2026"

# -------------------------------------------------------------
# STEP 1: Issue Warrant (Court Authority or Police)
# -------------------------------------------------------------
print(f"\n[Step 1] Issuing Smart Warrant '{warrant_num}' on-chain...")
r_reg = s_court.post(f'{BASE}/api/warrants/register', json={
    'warrant_number': warrant_num,
    'case_id': case_id,
    'duration_seconds': 3600 # 1 hour
})
assert r_reg.status_code == 201, f"Warrant registration failed: {r_reg.text}"
reg_json = r_reg.json()
print(f"  Issued: {warrant_num} | Valid until: {reg_json['valid_until']} | TX: {reg_json['tx_hash']}")

# -------------------------------------------------------------
# STEP 2: Access Control Check (Witness & Analyst)
# -------------------------------------------------------------
print("\n[Step 2] Testing Role Access Control...")
# Witness must have NO access to Smart Warrants
r_wit = s_witness.get(f'{BASE}/api/warrants')
print(f"  Witness GET /api/warrants -> Status: {r_wit.status_code} (Expected 403)")
assert r_wit.status_code == 403, f"Expected 403 for witness, got {r_wit.status_code}"

# Analyst must NOT be able to request or review extension
r_ana = s_analyst.post(f'{BASE}/api/warrants/{warrant_num}/request-extension', json={
    'additional_seconds': 86400,
    'reason': 'Analyst trying to extend'
})
print(f"  Analyst POST request-extension -> Status: {r_ana.status_code} (Expected 403)")
assert r_ana.status_code == 403, f"Expected 403 for analyst, got {r_ana.status_code}"

# -------------------------------------------------------------
# STEP 3: Police Requests Extension
# -------------------------------------------------------------
print(f"\n[Step 3] Officer Gordon requests extension for warrant '{warrant_num}'...")
# Test missing reason
r_no_reason = s_police.post(f'{BASE}/api/warrants/{warrant_num}/request-extension', json={
    'additional_seconds': 86400
})
print(f"  Request without reason -> Status: {r_no_reason.status_code} (Expected 400)")
assert r_no_reason.status_code == 400

# Valid request
r_req = s_police.post(f'{BASE}/api/warrants/{warrant_num}/request-extension', json={
    'additional_seconds': 86400,
    'reason': 'Forensic examination still in progress in central digital lab'
})
assert r_req.status_code == 201, f"Extension request failed: {r_req.text}"
req_json = r_req.json()
request_id = req_json['request_id']
print(f"  Extension Request #{request_id} Created:")
print(f"    Current Expiry:   {req_json['current_expiry']}")
print(f"    Requested Expiry: {req_json['requested_expiry']}")
print(f"    Reason:           {req_json['reason']}")
print(f"    Status:           {req_json['status']} (PENDING COURT APPROVAL)")

# -------------------------------------------------------------
# STEP 4: Conflict & Self-Approval Prevention
# -------------------------------------------------------------
print("\n[Step 4] Testing Conflict & Self-Approval Guards...")
# 4a. Multiple conflicting pending requests
r_conflict = s_police.post(f'{BASE}/api/warrants/{warrant_num}/request-extension', json={
    'additional_seconds': 172800,
    'reason': 'Duplicate conflicting request'
})
print(f"  Duplicate pending request -> Status: {r_conflict.status_code} (Expected 409 Conflict)")
assert r_conflict.status_code == 409, f"Expected 409, got {r_conflict.status_code}"

# 4b. Self-approval prevention (Officer attempting to approve own request)
r_self = s_police.post(f'{BASE}/api/warrants/extension-requests/{request_id}/review', json={
    'decision': 'approved',
    'decision_note': 'Officer attempting self-approval'
})
print(f"  Police self-approval attempt -> Status: {r_self.status_code} (Expected 403 Forbidden)")
assert r_self.status_code == 403, f"Expected 403, got {r_self.status_code}"

# -------------------------------------------------------------
# STEP 5: Court Authority Approves Extension
# -------------------------------------------------------------
print(f"\n[Step 5] Judge Wayne reviews and approves Extension Request #{request_id}...")
# Verify request appears in pending reviews
r_pend = s_court.get(f'{BASE}/api/warrants/extension-requests?status=pending')
assert r_pend.status_code == 200
pending_ids = [item['id'] for item in r_pend.json()]
assert request_id in pending_ids, f"Request #{request_id} not found in pending list"

# Execute approval
r_app = s_court.post(f'{BASE}/api/warrants/extension-requests/{request_id}/review', json={
    'decision': 'approved',
    'decision_note': 'Extension granted for digital laboratory analysis under Rule 4B'
})
assert r_app.status_code == 200, f"Approval failed: {r_app.text}"
app_json = r_app.json()
print(f"  Approval executed successfully:")
print(f"    Decision:       {app_json['decision']}")
print(f"    New Expiry:     {app_json['new_valid_until']}")
print(f"    Blockchain TX:  {app_json['tx_hash']}")

# -------------------------------------------------------------
# STEP 6: Rejection Workflow
# -------------------------------------------------------------
print("\n[Step 6] Testing Rejection Workflow...")
# Submit a second request now that previous is approved
r_req2 = s_police.post(f'{BASE}/api/warrants/{warrant_num}/request-extension', json={
    'additional_seconds': 3600,
    'reason': 'Secondary inspection requested'
})
assert r_req2.status_code == 201
req2_id = r_req2.json()['request_id']

# Judge rejects request
r_rej = s_court.post(f'{BASE}/api/warrants/extension-requests/{req2_id}/review', json={
    'decision': 'rejected',
    'decision_note': 'Denied: Sufficient time already granted in previous extension'
})
assert r_rej.status_code == 200
rej_json = r_rej.json()
print(f"  Request #{req2_id} rejected successfully: {rej_json['decision_note']}")

# -------------------------------------------------------------
# STEP 7: Verify Complete Warrant Audit History
# -------------------------------------------------------------
print(f"\n[Step 7] Verifying Immutable Audit Trail for Warrant '{warrant_num}'...")
r_detail = s_court.get(f'{BASE}/api/warrants/{warrant_num}')
assert r_detail.status_code == 200
w_detail = r_detail.json()
history = w_detail['extension_history']

print(f"\n=======================================================")
print(f"  WARRANT AUDIT TRAIL: {warrant_num}")
print(f"  Start Time:     {w_detail['start_time']}")
print(f"  Current Expiry: {w_detail['valid_until']}")
print(f"  Active Status:  {'Active On-Chain' if w_detail['is_valid'] else 'Expired'}")
print(f"  Total Extension Records: {len(history)}")
print(f"=======================================================")

for idx, h in enumerate(history, 1):
    print(f"  [{idx}] Request #{h['id']} · Status: {h['status'].upper()}")
    print(f"      Requested By:  {h['requester_name']} ({h['requester_role']})")
    print(f"      Previous -> Requested: {h['current_expiry']} -> {h['requested_expiry']}")
    print(f"      Reason:        {h['reason']}")
    if h['reviewed_at']:
        print(f"      Reviewed By:   {h['reviewer_name']} ({h['reviewer_role']}) at {h['reviewed_at']}")
        print(f"      Decision Note: {h['decision_note']}")
    if h['tx_hash']:
        print(f"      Blockchain TX: {h['tx_hash']}")

print(f"=======================================================")
print("SUCCESS: Smart Warrants two-party extension workflow and audit trail verified 100%!")
