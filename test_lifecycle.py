import requests
import io
import time

BASE = 'http://127.0.0.1:5000'

def login(email, password):
    s = requests.Session()
    r = s.post(f'{BASE}/api/auth/login', json={'email': email, 'password': password})
    assert r.status_code == 200, f"Login failed for {email}: {r.text}"
    return s

print("=== Starting 9-Stage Blockchain Evidence Lifecycle Verification ===")

# 1. Login all necessary roles
s_police = login('james.witness@forensic.gov', 'Password123!')
s_witness = login('witness@forensic.gov', 'Password123!')
s_analyst = login('analyst@forensic.gov', 'Password123!')
s_court = login('thomas.court@forensic.gov', 'Password123!')
s_investigator = login('sarah.investigator@forensic.gov', 'Password123!')

# Get witness user ID
r_wit_cand = s_police.get(f'{BASE}/api/users/witness-candidates')
assert r_wit_cand.status_code == 200
witness_users = [u for u in r_wit_cand.json() if u['email'] == 'witness@forensic.gov']
witness_id = witness_users[0]['id'] if witness_users else r_wit_cand.json()[0]['id']

# -------------------------------------------------------------
# STAGE 1: Evidence Uploaded / Seizure Initiated
# -------------------------------------------------------------
print("\n[Stage 1] Officer Gordon uploads evidence & initiates seizure...")
sample_bytes = f"Lifecycle test payload {time.time()}".encode('utf-8')
files = {'file': ('evidence_packet_9stage.log', io.BytesIO(sample_bytes), 'text/plain')}
data = {
    'case_id': 'CASE-LIFECYCLE-2026',
    'warrant_number': 'WR-9STAGE-001',
    'source_gps': '12.9716 N, 77.5946 E',
    'source_device_id': 'SERVER-RACK-07',
    'description': 'End-to-end 9-stage lifecycle evidence sample',
    'witness_user_id': str(witness_id),
}
r_up = s_police.post(f'{BASE}/api/upload_evidence', files=files, data=data)
print(f"  Upload response status: {r_up.status_code}")
assert r_up.status_code == 202, f"Upload failed: {r_up.text}"
up_json = r_up.json()
evidence_id = up_json['evidence_id']
file_hash = up_json['file_hash']
print(f"  Evidence ID: {evidence_id}")
print(f"  File SHA-256: {file_hash}")
print(f"  Upload TX Hash: {up_json['tx_hash']}")

# -------------------------------------------------------------
# STAGE 2: Witness Attested
# -------------------------------------------------------------
print("\n[Stage 2] Sworn Witness Elena Rostova attests seizure on-chain...")
r_attest = s_witness.post(f'{BASE}/api/seizure/attest', json={
    'evidence_id': evidence_id,
    'note': 'Sworn witness co-signed seizure at scene location'
})
print(f"  Attestation status: {r_attest.status_code}")
assert r_attest.status_code == 200, f"Attestation failed: {r_attest.text}"
attest_json = r_attest.json()
print(f"  Attestation TX Hash: {attest_json['tx_hash']}")

# -------------------------------------------------------------
# STAGE 3: Evidence Collected
# -------------------------------------------------------------
print("\n[Stage 3] Officer Gordon bags and collects evidence into secure custody...")
r_col = s_police.post(f'{BASE}/api/transfer_evidence', json={
    'evidence_id': evidence_id,
    'action': 'Evidence Collected',
    'note': 'Physical server drive packed in tamper-evident anti-static container'
})
print(f"  Collected status: {r_col.status_code}")
assert r_col.status_code == 200, f"Collection transfer failed: {r_col.text}"
print(f"  Collection TX: {r_col.json().get('tx_hash')}")

# -------------------------------------------------------------
# STAGE 4: Evidence Transferred
# -------------------------------------------------------------
print("\n[Stage 4] Det. Sarah Connor transfers evidence to Central Forensic Laboratory...")
r_trans = s_investigator.post(f'{BASE}/api/transfer_evidence', json={
    'evidence_id': evidence_id,
    'action': 'Evidence Transferred',
    'note': 'Chain-of-custody transfer from Police Station to Central Forensic Lab'
})
print(f"  Transferred status: {r_trans.status_code}")
assert r_trans.status_code == 200, f"Transfer failed: {r_trans.text}"
print(f"  Transfer TX: {r_trans.json().get('tx_hash')}")

# -------------------------------------------------------------
# STAGE 5: Forensic Analysis Started
# -------------------------------------------------------------
print("\n[Stage 5] Dr. Alan Turing starts forensic analysis in the digital lab...")
r_ana_start = s_analyst.post(f'{BASE}/api/transfer_evidence', json={
    'evidence_id': evidence_id,
    'action': 'Forensic Analysis Started',
    'note': 'Bit-stream image mounted for forensic inspection in write-blocker environment'
})
print(f"  Analysis Started status: {r_ana_start.status_code}")
assert r_ana_start.status_code == 200, f"Analysis start failed: {r_ana_start.text}"
print(f"  Analysis Started TX: {r_ana_start.json().get('tx_hash')}")

# -------------------------------------------------------------
# STAGE 6: Forensic Analysis Completed
# -------------------------------------------------------------
print("\n[Stage 6] Dr. Alan Turing completes forensic analysis...")
r_ana_done = s_analyst.post(f'{BASE}/api/transfer_evidence', json={
    'evidence_id': evidence_id,
    'action': 'Forensic Analysis Completed',
    'note': 'Artifacts extracted, timeline reconstructed, preliminary report generated'
})
print(f"  Analysis Completed status: {r_ana_done.status_code}")
assert r_ana_done.status_code == 200, f"Analysis complete failed: {r_ana_done.text}"
print(f"  Analysis Completed TX: {r_ana_done.json().get('tx_hash')}")

# -------------------------------------------------------------
# STAGE 7: Evidence Verified
# -------------------------------------------------------------
print("\n[Stage 7] Dr. Alan Turing executes cryptographic verification check on-chain...")
r_ver = s_analyst.post(f'{BASE}/api/verify_evidence', json={
    'evidence_id': evidence_id,
    'current_hash': file_hash
})
print(f"  Verification status: {r_ver.status_code}")
assert r_ver.status_code == 200, f"Verification failed: {r_ver.text}"
ver_json = r_ver.json()
print(f"  Integrity intact: {ver_json.get('intact')} | Verified on blockchain: {ver_json.get('custody_blockchain_confirmed')}")
print(f"  Verification TX: {ver_json.get('custody_tx_hash')}")

# -------------------------------------------------------------
# STAGE 8: Evidence Presented to Court
# -------------------------------------------------------------
print("\n[Stage 8] Judge Wayne records evidence presentation during judicial proceedings...")
r_court = s_court.post(f'{BASE}/api/transfer_evidence', json={
    'evidence_id': evidence_id,
    'action': 'Evidence Presented to Court',
    'note': 'Exhibit A admitted in Special Sessions Court No. 4'
})
print(f"  Presented status: {r_court.status_code}")
assert r_court.status_code == 200, f"Court presentation failed: {r_court.text}"
print(f"  Presented TX: {r_court.json().get('tx_hash')}")

# -------------------------------------------------------------
# STAGE 9: Evidence Stored / Court-Sealed
# -------------------------------------------------------------
print("\n[Stage 9] Judge Wayne seals and stores evidence in the official court archive...")
r_seal = s_court.post(f'{BASE}/api/evidence/{evidence_id}/seal')
print(f"  Court seal status: {r_seal.status_code}")
assert r_seal.status_code == 200, f"Sealing failed: {r_seal.text}"
seal_json = r_seal.json()
print(f"  Sealing TX: {seal_json.get('tx_metadata', {}).get('tx_hash')}")

# -------------------------------------------------------------
# VERIFY COMPLETE 9-STAGE LIFECYCLE API
# -------------------------------------------------------------
print("\n[Verification] Fetching structured 9-stage lifecycle report...")
r_life = s_court.get(f'{BASE}/api/evidence/{evidence_id}/lifecycle')
assert r_life.status_code == 200
life_data = r_life.json()
stages = life_data['stages']

print(f"\n=======================================================")
print(f"  LIFECYCLE STATUS REPORT: {evidence_id}")
print(f"  Completed: {life_data['completed_count']}/{life_data['total_stages']} stages")
print(f"=======================================================")
all_confirmed = True
for s in stages:
    icon = "[OK]" if s['status'] == 'completed' else "[..]"
    bc_icon = "CONFIRMED" if s['blockchain_status'] == 'Blockchain Confirmed' else s['blockchain_status']
    print(f" {icon} Stage {s['stage']}: {s['name']}")
    print(f"    Status: {s['status']} | Blockchain: {bc_icon}")
    if s['tx_hash']:
        print(f"    TX: {s['tx_hash'][:24]}... | Actor: {s['actor']}")
    if s['blockchain_status'] != 'Blockchain Confirmed':
        all_confirmed = False

print(f"=======================================================")
if all_confirmed:
    print("SUCCESS: All 9 lifecycle stages successfully recorded & confirmed on blockchain!")
else:
    print("WARNING: Some stages did not get Blockchain Confirmed status.")
