# EviBlock: An AI-Enhanced Blockchain Framework for Digital Evidence Management

> An enterprise-grade, multi-tier Digital Forensics & Chain of Custody platform combining **Ethereum Smart Contracts**, an **Isolation Forest ML anomaly engine**, and **AI-powered legal case synthesis** to guarantee tamper-proof evidentiary integrity from field seizure to court verdict.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Quick Start (Windows — 1-Click)](#quick-start-windows--1-click)
- [Manual Setup](#manual-setup)
- [Environment Variables](#environment-variables)
- [Login Credentials](#login-credentials)
- [User Roles & Permissions](#user-roles--permissions)
- [Key Features](#key-features)
- [API Reference](#api-reference)
- [Smart Contract Functions](#smart-contract-functions)
- [Demo Workflow](#demo-workflow)
- [Sample Evidence Files](#sample-evidence-files)
- [Offline Mode](#offline-mode)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

ForensicChain is built on a **4-Tier Integrity Model**:

```
+------------------+--------------------+---------------------------------+
| TIER             | TECHNOLOGY         | ROLE & LEGAL AUTHORITY          |
+------------------+--------------------+---------------------------------+
| Tier 1: Storage  | SQLite ACID Store  | Fast operational metadata       |
| Tier 2: Trust    | Ethereum Blockchain| AUTHORITATIVE SHA-256 Anchor    |
| Tier 3: Advisory | AI Legal Engine    | Non-Authoritative Case Summary  |
| Tier 4: Security | ML Isolation Forest| Behavioral Anomaly Detection    |
+------------------+--------------------+---------------------------------+
```

> **Key Design Principle**: Cryptographic SHA-256 and blockchain consensus are the **sole authoritative integrity mechanism**. AI and ML operate strictly as **advisory, read-only auxiliary layers** — they cannot alter evidence status, change cryptographic verdicts, or auto-extend legal warrants.

---

## Project Structure

```
ForensicChain/
|
+-- backend/
|   +-- app.py                  # Flask REST API — main entry point
|   +-- blockchain.py           # Web3.py Ethereum/Ganache interaction layer
|   +-- database.py             # SQLite database helpers & schema
|   +-- eviblock.db             # SQLite database (auto-created)
|   +-- contract_address.txt    # Deployed smart contract address
|
+-- contracts/
|   +-- Evidence.sol            # Solidity smart contract (Evidence + Warrants)
|   +-- Evidence_abi.json       # Generated ABI (after deployment)
|
+-- frontend/
|   +-- index.html              # Login page
|   +-- dashboard.html          # Full dashboard (all roles)
|   +-- reset-password.html     # Password reset page
|   +-- forensic-label.js       # Forensic label JS component
|   +-- signature-pad.js        # Digital signature pad
|
+-- ml/
|   +-- anomaly_detector.py     # Isolation Forest anomaly detection engine
|   +-- feature_engineering.py  # 12-dimensional feature vector builder
|   +-- train_model.py          # Model training script
|   +-- model/                  # Trained ML model artifacts
|
+-- ai/
|   +-- case_summary.py         # AI legal case summary generator
|   +-- warrant_advisor.py      # Smart Warrant AI advisor engine
|
+-- migrations/
|   +-- deploy.py               # Smart contract compile + deploy script
|
+-- evidence_storage/           # Uploaded evidence files stored here
+-- sample_evidences/           # Pre-built sample evidence files for demos
+-- requirements.txt            # Python dependencies
+-- .env                        # Environment configuration
+-- START_APP.bat               # Windows one-click launcher
```

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| Blockchain | Ethereum (Ganache local testnet, port 7545) |
| Smart Contract | Solidity 0.8.x |
| Backend | Python 3.9+, Flask 3.1 |
| Blockchain SDK | Web3.py 7.x |
| Database | SQLite (via Python `sqlite3`) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| ML Engine | Isolation Forest (unsupervised anomaly detection) |
| AI Engine | Rule-based + LLM synthesis (case summaries, warrant advisor) |
| Hashing | SHA-256 (`hashlib`) |
| Auth | Flask sessions + Werkzeug + PyJWT + bcrypt |
| Signing | Digital signature pad (ECDSA-style witness attestation) |

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.9+ | https://python.org |
| Node.js | 18+ | https://nodejs.org |
| Ganache CLI | latest | `npm install -g ganache` |
| pip | latest | Included with Python |

---

## Quick Start (Windows — 1-Click)

1. Make sure **Node.js** and **Python** are installed and in your PATH.
2. Double-click **`START_APP.bat`** in the project root.

The script automatically:
- Starts **Ganache** blockchain node on port `7545`
- Launches the **Flask backend** on `http://localhost:5000`
- Opens **Google Chrome** at `http://localhost:5000`

> Keep the terminal window open while using the app. Press `Ctrl+C` to stop.

---

## Manual Setup

### Step 1 — Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 2 — Start Ganache (Blockchain Node)

Open a dedicated terminal and run:

```bash
npx ganache --port 7545 --wallet.deterministic
```

Keep this terminal running in the background.

### Step 3 — Configure Environment

Edit `.env` in the project root (or copy from `.env.example`):

```env
GANACHE_URL=http://127.0.0.1:7545
CONTRACT_ADDRESS=0x5b1869D9A4C187F2EAa108f3062412ecf0526b24
SECRET_KEY=forensic-chain-secret-key-2024
PORT=5000
DATABASE_URL=sqlite:///./backend/eviblock.db
ADMIN_EMAIL=admin@forensic.local
ADMIN_PASSWORD=Admin@12345
```

### Step 4 — Start the Backend

```bash
python backend/app.py
```

Server starts at: **http://localhost:5000**

### Step 5 — Open the Application

Open your browser to **http://localhost:5000**

The Flask server serves the frontend directly — no separate frontend build step is needed.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GANACHE_URL` | `http://127.0.0.1:7545` | Ganache RPC endpoint |
| `CONTRACT_ADDRESS` | *(from contract_address.txt)* | Deployed Evidence contract address |
| `SECRET_KEY` | `forensic-chain-secret-key-2024` | Flask session secret |
| `PORT` | `5000` | Flask server port |
| `DATABASE_URL` | `sqlite:///./backend/eviblock.db` | SQLite DB path |
| `ADMIN_EMAIL` | `admin@forensic.local` | Admin account email |
| `ADMIN_PASSWORD` | `Admin@12345` | Admin account password |
| `JWT_SECRET` | `forensic-chain-jwt-secret-key-2024` | JWT signing secret |
| `JWT_EXPIRATION_HOURS` | `8` | JWT token lifespan |
| `SESSION_TIMEOUT_HOURS` | `8` | Session expiry duration |

---

## Login Credentials

| Role | Email | Password |
|------|-------|----------|
| **System Administrator** | `admin@forensic.local` | `Admin@12345` |
| **Court Authority (Judge)** | `thomas.court@forensic.gov` | `Password123!` |
| **Police Officer** | `james.witness@forensic.gov` | `Password123!` |
| **Forensic Analyst** | `analyst@forensic.gov` | `Password123!` |
| **Independent Witness** | `witness@forensic.gov` | `Password123!` |
| **Investigator** | `sarah.investigator@forensic.gov` | `Password123!` |

> **URL**: `http://localhost:5000/`

---

## User Roles & Permissions

| Role | Permissions |
|------|-------------|
| `admin` | Full access — user management, blockchain node, Merkle batching, system audit |
| `investigator` | Field evidence upload, custody tracking, warrant search & extension requests |
| `witness` | Co-sign seizure handshakes (witness attestation), view pending attestations |
| `analyst` | Cryptographic verification, ML anomaly scans, evidence branching, chain of custody |
| `court_authority` | Issue smart warrants, approve/reject warrant extensions, seal evidence, public verification links |

---

## Key Features

### 1. Two-Factor Seizure Handshake
Evidence upload requires: Case ID, Warrant Number, GPS Coordinates, Source Device ID, and a designated independent witness. The upload enters **Pending Witness Approval** state and only becomes active after the witness digitally attests.

### 2. SHA-256 Tamper Detection
Every evidence file is SHA-256 hashed at upload time and the hash is anchored on-chain. Verification re-hashes the stored file and compares it bit-for-bit against the blockchain — any modification is instantly detected.

### 3. Smart Warrants (On-Chain)
Judges issue time-bound search warrants directly onto the Ethereum smart contract. Warrants have live countdown timers. Police can request extensions; judges approve or reject extensions — all written immutably on-chain.

### 4. AI Warrant Advisor
The AI advisor evaluates investigation workflow progress and generates a recommendation gauge (0–100%) to inform judicial extension decisions. The AI cannot auto-approve — human judicial review is legally mandatory.

### 5. AI Legal Case Summary
Generates structured case reports per Case ID:
- Confirmed evidence count and integrity status
- Blockchain confirmation summary
- AI-synthesized executive narrative (no hallucinations, no guilt conclusions)
- Mandatory legal disclaimer for human review

### 6. ML Behavioral Anomaly Detection (Isolation Forest)
An unsupervised Isolation Forest model evaluates a **12-dimensional feature vector** over audit logs:
- Access frequency, failed attempts, transfer velocity
- Unique actor diversity, off-hours access patterns
- Outputs: Anomaly Score (0.0–1.0) + Risk Tier (LOW / MEDIUM / HIGH)

### 7. Merkle Tree Batching (Gas Optimization)
Instead of writing N blockchain transactions for N evidence files, ForensicChain builds an O(log N) Merkle tree and commits a **single 32-byte root on-chain**. Inclusion of any file can be cryptographically proven with a compact O(log N) proof.

### 8. Non-Destructive Evidence Branching
Forensic analysts can create derived child evidence artifacts linked to a parent evidence ID. The original parent hash is fully preserved while lineage is recorded in custody metadata.

### 9. Court Sealing & Finality
Court authorities can permanently seal evidence. Once sealed, all custody mutations, status changes, and branches are blocked — providing legal finality.

### 10. One-Time Public Verification Links
Court authorities generate expiring, single-use verification tokens for third-party validation (e.g., defense counsel) without exposing internal databases.

### 11. Multi-Admin Break-Glass Control
Deactivating investigator accounts requires a two-admin approval flow: Admin A creates the request; Admin B must approve it — preventing unilateral account manipulation.

### 12. Subpoena-Style Private Access
Evidence can be marked private. Non-owner access requires a reasoned access request; the owner can approve or reject it. Every request is logged for audit visibility.

---

## API Reference

All endpoints require session authentication unless noted.

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user |
| POST | `/api/auth/login` | Login |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/auth/me` | Get current user info |

### Evidence

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload_evidence` | Upload file + initiate seizure handshake |
| GET | `/api/evidence` | List all accessible evidence |
| GET | `/api/evidence/<id>` | Evidence detail + custody logs |
| POST | `/api/verify_evidence` | Verify hash integrity |
| POST | `/api/transfer_evidence` | Add custody action |
| GET | `/api/evidence_history/<id>` | Full custody chain |
| POST | `/api/seizure/attest` | Witness attestation (co-sign) |
| POST | `/api/evidence/branch` | Create child evidence branch |
| POST | `/api/evidence/<id>/request-access` | Request private evidence access |
| GET | `/api/evidence/access-requests` | View access requests |
| POST | `/api/evidence/access-requests/<request_id>/review` | Approve/reject access request |
| POST | `/api/evidence/<id>/seal` | Seal evidence (court authority) |
| POST | `/api/evidence/<id>/verification-link` | Generate one-time public verification link |
| POST | `/api/public/verify` | Public file verification (token-based, no auth required) |

### Smart Warrants

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/warrants` | Issue new smart warrant (on-chain) |
| GET | `/api/warrants` | List all warrants |
| GET | `/api/warrants/<id>` | Warrant detail + status |
| POST | `/api/warrants/<id>/request-extension` | Request warrant time extension |
| POST | `/api/warrants/<id>/approve-extension` | Approve warrant extension (judge) |
| GET | `/api/warrants/<id>/ai-advisor` | Get AI warrant advisor recommendation |

### ML & AI

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ml/scan/<evidence_id>` | Run Isolation Forest anomaly scan |
| GET | `/api/ml/reports` | List all ML anomaly reports |
| POST | `/api/ai/case-summary` | Generate AI legal case summary |

### Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/users` | All users (admin only) |
| GET | `/api/admin/stats` | System statistics |
| GET | `/api/admin/logs` | All custody logs |
| GET | `/api/admin/actions/pending` | Pending multi-admin actions |
| POST | `/api/admin/actions/<action_id>/approve` | Approve pending admin action |

### Blockchain & Merkle

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/blockchain/info` | Network status + block info |
| POST | `/api/blockchain/deploy` | Deploy contract (admin) |
| POST | `/api/blockchain/set_address` | Set contract address (admin) |
| POST | `/api/merkle/batch` | Create and commit Merkle batch on-chain |
| GET | `/api/merkle/verify` | Verify Merkle inclusion proof |

### Utilities

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users/witness-candidates` | List eligible witness users |
| GET | `/health` | Health check (DB + blockchain connectivity) |

---

## Smart Contract Functions

```solidity
// Register new evidence on blockchain
addEvidence(evidenceId, fileHash, fileName, caseId)

// Record custody action (transfer, analyze, seal, etc.)
transferEvidence(evidenceId, action, note)

// Read evidence from blockchain
getEvidence(evidenceId) -> (fileHash, fileName, caseId, owner, timestamp)

// Get custody record count
getCustodyCount(evidenceId) -> uint256

// Get individual custody record
getCustodyRecord(evidenceId, index) -> (action, actor, note, timestamp)

// Check if evidence exists
evidenceExists(evidenceId) -> bool

// Issue a time-bound smart warrant
issueWarrant(warrantId, caseId, durationSeconds)

// Approve a warrant extension (on-chain, judge only)
approveExtension(warrantId, additionalSeconds)

// Check warrant validity
isWarrantValid(warrantId) -> bool
```

---

## Demo Workflow

Follow this sequence to demonstrate the full platform during a presentation:

### Phase 1 — Court Issues Smart Warrant
1. Login as `thomas.court@forensic.gov` / `Password123!`
2. Go to **Smart Warrants** and issue a warrant:
   - Warrant No: `WR-2026-COURT-99` | Case ID: `CASE-2026-09` | Duration: 24 Hours
3. An Ethereum Transaction Hash is generated instantly. Logout.

### Phase 2 — Police Field Seizure
1. Login as `james.witness@forensic.gov` / `Password123!`
2. Go to **Upload Evidence** and upload `sample_evidences/01_cctv_access_log.log`
3. Fill in: Case ID, Warrant No, GPS (`17.3850, 78.4867`), Device ID, Witness user
4. Click **"Initiate Seizure Handshake"** — Status: **Pending Witness Approval**. Logout.

### Phase 3 — Witness Attestation
1. Login as `witness@forensic.gov` / `Password123!`
2. Go to **Pending Attestations** and click **"Approve & Sign"**
3. Enter attestation note and submit — Evidence is now **Active** and SHA-256 is anchored on-chain. Logout.

### Phase 4 — Chain of Custody
1. Go to **Chain of Custody** and enter the Evidence ID
2. Add action: `Forensic Analysis Started`. Logout.

### Phase 5 — Verify Integrity (Pass)
1. Login as `analyst@forensic.gov` / `Password123!`
2. Go to **Verify Evidence** and click **"Verify Integrity"**
3. Result: **GREEN** — `VERIFIED / INTEGRITY CONFIRMED`

### Phase 6 — Tamper Detection (Fail)
1. Open `evidence_storage/` in File Explorer
2. Open the uploaded file in Notepad, change one character, and Save
3. Go back to the browser and click **"Verify Integrity"** again
4. Result: **RED** — `TAMPER DETECTED / INTEGRITY BREACH`
   - The blockchain hash never changed — only the file did. This proves tamper detection is working.

### Phase 7 — Merkle Batching (Admin)
1. Login as `admin@forensic.local` / `Admin@12345`
2. Go to **Merkle Batching**, select evidence items, click **"Commit Merkle Root On-Chain"**
3. Click **"Verify Merkle Proof"** — Result: **VALID PROOF** — O(log N) gas savings demonstrated.

---

## Sample Evidence Files

Located in `sample_evidences/`:

| File | Description |
|------|-------------|
| `01_cctv_access_log.log` | Biometric server room door access log |
| `02_ransomware_demand_note.txt` | LockBit 3.0 cyber extortion note |
| `03_bank_fraud_transfer.csv` | Fraudulent bank transaction ledger |
| `04_network_intrusion_alert.log` | SSH brute-force and root exploit dump |
| `05_suspect_chat_export.txt` | Signal private messenger chat dump |
| `06_malware_indicators_of_compromise.json` | Malware C2 servers & SHA-256 IOCs |

---

## Offline Mode

If Ganache is not running, the system operates in **offline fallback mode**:
- Evidence files are still uploaded and SHA-256 hashed
- Metadata is saved to SQLite with ACID transactions
- Transaction hashes are prefixed with `OFFLINE-`
- Verification compares against the DB hash (not blockchain)
- When blockchain connectivity is restored, records are reconciled on-chain

---

## Troubleshooting

**"Invalid credentials" on login**

Run this once to reset the admin password directly in the database:
```bash
python reset_admin.py
```
Restart the backend and try again with `admin@forensic.local` / `Admin@12345`.

---

**"Cannot connect to Ganache"**
- Ensure Ganache is running: `npx ganache --port 7545 --wallet.deterministic`
- Check the port in `.env`: `GANACHE_URL=http://127.0.0.1:7545`

---

**"Contract not deployed" / Blockchain shows disconnected**
- The contract address in `.env` and `backend/contract_address.txt` must match the running Ganache session
- If Ganache was restarted in non-deterministic mode, redeploy: `python deploy_contract.py`

---

**"py-solc-x compile error"**
- First compile downloads the Solidity compiler (~50 MB) — requires an internet connection
- If behind a proxy: `set HTTPS_PROXY=your_proxy`

---

**Port 5000 already in use**
- Change the port in `.env`: `PORT=5001`
- Or find and kill the process using the port:
  ```powershell
  netstat -ano | findstr :5000
  taskkill /PID <pid> /F
  ```

---

**ModuleNotFoundError on startup**
```bash
pip install -r requirements.txt
```
Ensure you are running in the correct Python environment (check with `python --version`).
