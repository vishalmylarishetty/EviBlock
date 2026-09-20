import requests
import json
import time
import io
import sys

BASE_URL = "http://127.0.0.1:5000"

def login(email, password):
    s = requests.Session()
    res = s.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": password})
    if res.status_code != 200:
        raise RuntimeError(f"Login failed for {email}: {res.text}")
    return s

def run_tests():
    print("=== Starting Enhanced Merkle Batching Verification ===")

    # 1. Log in users
    admin_s = login("admin@forensic.local", "Admin@12345")
    court_s = login("thomas.court@forensic.gov", "Password123!")
    police_s = login("james.witness@forensic.gov", "Password123!")
    analyst_s = login("analyst@forensic.gov", "Password123!")
    witness_s = login("witness@forensic.gov", "Password123!")

    # Step 1: Role Access Control
    print("\n[Step 1] Testing Role-Based Access Control...")
    
    # Police cannot get batches
    r = police_s.get(f"{BASE_URL}/api/merkle/batches")
    assert r.status_code == 403, f"Expected 403 for police, got {r.status_code}"
    print("  Police GET /api/merkle/batches -> Status: 403 (Expected 403)")

    # Witness cannot get batches
    r = witness_s.get(f"{BASE_URL}/api/merkle/batches")
    assert r.status_code == 403, f"Expected 403 for witness, got {r.status_code}"
    print("  Witness GET /api/merkle/batches -> Status: 403 (Expected 403)")

    # Analyst cannot get batches
    r = analyst_s.get(f"{BASE_URL}/api/merkle/batches")
    assert r.status_code == 403, f"Expected 403 for analyst, got {r.status_code}"
    print("  Analyst GET /api/merkle/batches -> Status: 403 (Expected 403)")

    # Court authority cannot create batches
    r = court_s.post(f"{BASE_URL}/api/merkle/batch/evidence", json={"evidence_ids": ["dummy"]})
    assert r.status_code == 403, f"Expected 403 for court batch creation, got {r.status_code}"
    print("  Court Authority POST /api/merkle/batch/evidence -> Status: 403 (Expected 403)")

    # Step 2: Register test warrant & create fresh evidence records
    print("\n[Step 2] Registering test warrant & generating fresh test evidence records...")
    t = int(time.time())
    warrant_num = f"WR-MB-{t}"
    w_res = court_s.post(f"{BASE_URL}/api/warrants/register", json={
        "warrant_number": warrant_num,
        "case_id": f"CASE-MB-{t}",
        "duration_seconds": 86400
    })
    assert w_res.status_code == 201, f"Failed to register warrant: {w_res.text}"
    print(f"  Issued Test Warrant: {warrant_num}")

    r_wit = police_s.get(f"{BASE_URL}/api/users/witness-candidates")
    witness_id = r_wit.json()[0]["id"] if r_wit.status_code == 200 and r_wit.json() else 1

    fresh_ids = []
    original_hashes = {}

    for i in range(2):
        content = f"Merkle test evidence content {t}_{i}".encode('utf-8')
        files = {'file': (f'merkle_test_doc_{t}_{i}.txt', io.BytesIO(content), 'text/plain')}
        data = {
            'case_id': f'CASE-MB-{t}',
            'warrant_number': warrant_num,
            'source_gps': '12.9716 N, 77.5946 E',
            'source_device_id': f'DEVICE-MB-{i+1}',
            'witness_user_id': str(witness_id),
            'description': f'Merkle Batching Test Evidence #{i+1}',
        }
        up = police_s.post(f"{BASE_URL}/api/upload_evidence", files=files, data=data)
        assert up.status_code == 202, f"Upload failed: {up.text}"
        ev_id = up.json()["evidence_id"]
        fresh_ids.append(ev_id)

        # Get stored hash
        ev_info = admin_s.get(f"{BASE_URL}/api/evidence/{ev_id}").json()["evidence"]
        orig_hash = ev_info.get("file_hash") or ev_info.get("hash")
        original_hashes[ev_id] = orig_hash
        print(f"  Created test evidence: {ev_id} | Hash: {orig_hash[:20]}...")

    # Step 3: Admin creates Merkle batch from selected evidence
    print("\n[Step 3] Admin creates Merkle batch from selected evidence...")
    batch_case_id = f"CASE-BATCH-{t}"
    create_res = admin_s.post(f"{BASE_URL}/api/merkle/batch/evidence", json={
        "evidence_ids": fresh_ids,
        "case_id": batch_case_id
    })
    assert create_res.status_code == 201, f"Batch creation failed: {create_res.text}"
    batch_data = create_res.json()
    batch_id = batch_data["batch_id"]
    batch_label = batch_data["batch_label"]
    root_hash = batch_data["root_hash"]
    tx_hash = batch_data["tx_hash"]
    item_count = batch_data["item_count"]
    status = batch_data["blockchain_status"]

    print(f"  Batch Created Successfully:")
    print(f"    Batch ID:          {batch_label} (#{batch_id})")
    print(f"    Evidence Count:    {item_count}")
    print(f"    Merkle Root:       {root_hash}")
    print(f"    Blockchain Status: {status}")
    print(f"    Transaction:       {tx_hash}")

    # Step 4: Test Duplicate Batch Guard (Conflict 409)
    print("\n[Step 4] Testing Duplicate Batch Commitment Guard...")
    dup_res = admin_s.post(f"{BASE_URL}/api/merkle/batch/evidence", json={
        "evidence_ids": fresh_ids,
        "case_id": batch_case_id
    })
    assert dup_res.status_code == 409, f"Expected 409 Conflict, got {dup_res.status_code}: {dup_res.text}"
    print(f"  Duplicate batch attempt -> Status: 409 Conflict (Expected)")

    # Step 5: Court Authority reads batch history
    print("\n[Step 5] Court Authority accesses Merkle batch history (Read-Only)...")
    court_batches_res = court_s.get(f"{BASE_URL}/api/merkle/batches")
    assert court_batches_res.status_code == 200, f"Court cannot view batches: {court_batches_res.text}"
    batches = court_batches_res.json()
    found = any(b.get("id") == batch_id or b.get("root_hash") == root_hash for b in batches)
    assert found, "Created batch not found in court authority batch list"
    print(f"  Court Authority listed {len(batches)} batches (Read-only confirmed)")

    # Step 6: Verification of individual evidence within batch
    print("\n[Step 6] Verifying individual evidence against Merkle batch...")
    target_ev_id = fresh_ids[0]

    v_res = court_s.post(f"{BASE_URL}/api/merkle/batch/{batch_id}/verify-evidence", json={
        "evidence_id": target_ev_id
    })
    assert v_res.status_code == 200, f"Verification request failed: {v_res.text}"
    v_data = v_res.json()
    assert v_data["valid"] is True, f"Expected valid=True, got {v_data}"
    assert v_data["result"] == "VALID"
    print(f"  Court Authority verification of '{target_ev_id}' in {batch_label}:")
    print(f"    Result:              VALID [OK]")
    print(f"    Leaf Hash:           {v_data['leaf_hash'][:28]}...")
    print(f"    Proof Length:        O(log N) = {v_data['proof_length']}")
    print(f"    Blockchain Verified: {v_data['blockchain_verified']}")

    # Step 7: Non-member evidence check
    print("\n[Step 7] Testing non-member evidence verification...")
    non_member_res = court_s.post(f"{BASE_URL}/api/merkle/batch/{batch_id}/verify-evidence", json={
        "evidence_id": "EV-NON-EXISTENT-999"
    })
    assert non_member_res.status_code == 404, f"Expected 404, got {non_member_res.status_code}"
    print(f"  Non-member evidence check -> Status: 404 NOT_IN_BATCH (Expected)")

    # Step 8: Manual proof verification with tampered leaf
    print("\n[Step 8] Testing tampered hash verification...")
    tampered_leaf = "0x" + "f" * 64
    tampered_res = court_s.post(f"{BASE_URL}/api/merkle/verify", json={
        "leaf_hash": tampered_leaf,
        "root_hash": root_hash,
        "proof": ["0x" + "a" * 64]
    })
    assert tampered_res.status_code == 200
    assert tampered_res.json()["valid"] is False, "Tampered hash should be invalid"
    print(f"  Tampered hash verification -> valid: False -> INTEGRITY CHECK FAILED (Expected)")

    # Step 9: Verify original evidence records are completely unaltered
    print("\n[Step 9] Verifying original evidence records integrity...")
    for ev_id, orig_hash in original_hashes.items():
        check_res = admin_s.get(f"{BASE_URL}/api/evidence/{ev_id}")
        assert check_res.status_code == 200
        ev_payload = check_res.json().get("evidence", {})
        current_hash = ev_payload.get("file_hash") or ev_payload.get("hash")
        assert current_hash == orig_hash, f"Evidence {ev_id} hash was altered! Original: {orig_hash}, Current: {current_hash}"
    print(f"  CONFIRMED: All {len(original_hashes)} original evidence records and SHA-256 hashes remain 100% UNTOUCHED.")

    print("\n=======================================================")
    print("SUCCESS: Enhanced Merkle Batching verified 100%!")
    print("=======================================================")

if __name__ == "__main__":
    run_tests()
