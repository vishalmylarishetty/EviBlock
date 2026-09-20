import requests

BASE = 'http://127.0.0.1:5000'

def test_login_and_perms(email, password, expected_role):
    s = requests.Session()
    r = s.post(f'{BASE}/api/auth/login', json={'email': email, 'password': password})
    if r.status_code != 200:
        print(f'FAIL login {email}: {r.status_code} {r.text}')
        return
    user = r.json().get('user', {})
    role = user.get('role')
    print(f"\n=== Testing User: {user.get('name')} ({user.get('email')}) | Role: {role} ===")
    assert role == expected_role, f"Expected {expected_role}, got {role}"

    # 1. Upload evidence (allowed: investigator, police, admin)
    r_up = s.post(f'{BASE}/api/upload_evidence', data={'case_id': 'TEST-1'})
    # Expect 400 (validation failure) if authorized, 403 if forbidden
    print(f"  POST /api/upload_evidence -> Status: {r_up.status_code} ({'AUTHORIZED' if r_up.status_code != 403 else 'FORBIDDEN 403'})")

    # 2. Merkle batch (allowed: admin only)
    r_mb = s.post(f'{BASE}/api/merkle/batch', json={'evidence_ids': []})
    print(f"  POST /api/merkle/batch -> Status: {r_mb.status_code} ({'AUTHORIZED' if r_mb.status_code != 403 else 'FORBIDDEN 403'})")

    # 3. Witness pending attestations (allowed: witness, admin, investigator, police)
    r_wp = s.get(f'{BASE}/api/witness/pending')
    print(f"  GET /api/witness/pending -> Status: {r_wp.status_code} ({'AUTHORIZED' if r_wp.status_code != 403 else 'FORBIDDEN 403'})")

    # 4. Smart warrant register (allowed: court_authority, admin, investigator, police)
    r_war = s.post(f'{BASE}/api/warrants/register', json={})
    print(f"  POST /api/warrants/register -> Status: {r_war.status_code} ({'AUTHORIZED' if r_war.status_code != 403 else 'FORBIDDEN 403'})")

    # 5. Branch evidence (allowed: analyst, investigator, admin)
    r_br = s.post(f'{BASE}/api/evidence/branch', json={})
    print(f"  POST /api/evidence/branch -> Status: {r_br.status_code} ({'AUTHORIZED' if r_br.status_code != 403 else 'FORBIDDEN 403'})")

# Run tests
test_login_and_perms('admin@forensic.local', 'Admin@12345', 'admin')
test_login_and_perms('sarah.investigator@forensic.gov', 'Password123!', 'investigator')
test_login_and_perms('james.witness@forensic.gov', 'Password123!', 'police')
test_login_and_perms('analyst@forensic.gov', 'Password123!', 'analyst')
test_login_and_perms('thomas.court@forensic.gov', 'Password123!', 'court_authority')
test_login_and_perms('witness@forensic.gov', 'Password123!', 'witness')
