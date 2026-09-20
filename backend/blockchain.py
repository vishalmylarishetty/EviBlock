import os
from threading import Lock
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

# Handle different versions of web3.py
try:
    # Older versions
    from web3.middleware import geth_poa_middleware
except ImportError:
    try:
        # Newer versions (7.x)
        from web3.middleware import ExtraDataToPOAMiddleware
        geth_poa_middleware = ExtraDataToPOAMiddleware()
    except ImportError:
        geth_poa_middleware = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

# Explicit RPC_URL takes precedence. For local demo environments, prefer GANACHE_URL
# over ALCHEMY_API_URL when both are present to avoid accidental network mismatch.
RPC_URL = (
    os.getenv("RPC_URL")
    or os.getenv("GANACHE_URL")
    or os.getenv("ALCHEMY_API_URL")
    or "http://127.0.0.1:7545"
)
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
TX_RECEIPT_TIMEOUT_SEC = int(os.getenv("TX_RECEIPT_TIMEOUT_SEC", "120"))
DEFAULT_CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")
CONTRACT_ADDRESS_FILE = os.path.join(os.path.dirname(__file__), "contract_address.txt")
ABI_FILE = os.path.join(os.path.dirname(__file__), "..", "contracts", "Evidence_abi.json")
ERR_BLOCKCHAIN_NOT_READY = "Blockchain not connected or contract not deployed"

# EvidenceManagement ABI (generated from Evidence.sol)
CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "string", "name": "_id", "type": "string"},
            {"internalType": "string", "name": "_hash", "type": "string"},
            {"internalType": "string", "name": "_fileName", "type": "string"},
            {"internalType": "string", "name": "_caseId", "type": "string"}
        ],
        "name": "addEvidence",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "_id", "type": "string"},
            {"internalType": "string", "name": "_action", "type": "string"},
            {"internalType": "string", "name": "_note", "type": "string"}
        ],
        "name": "transferEvidence",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "_id", "type": "string"}],
        "name": "getEvidence",
        "outputs": [
            {"internalType": "string", "name": "fileHash", "type": "string"},
            {"internalType": "string", "name": "fileName", "type": "string"},
            {"internalType": "string", "name": "caseId", "type": "string"},
            {"internalType": "address", "name": "owner", "type": "address"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "_id", "type": "string"}],
        "name": "getCustodyCount",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "_id", "type": "string"},
            {"internalType": "uint256", "name": "index", "type": "uint256"}
        ],
        "name": "getCustodyRecord",
        "outputs": [
            {"internalType": "string", "name": "action", "type": "string"},
            {"internalType": "address", "name": "actor", "type": "address"},
            {"internalType": "string", "name": "note", "type": "string"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "_id", "type": "string"}],
        "name": "evidenceExists",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "internalType": "string", "name": "evidenceId", "type": "string"},
            {"indexed": False, "internalType": "string", "name": "fileHash", "type": "string"},
            {"indexed": True, "internalType": "address", "name": "owner", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "name": "EvidenceAdded",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "internalType": "string", "name": "evidenceId", "type": "string"},
            {"indexed": False, "internalType": "string", "name": "action", "type": "string"},
            {"indexed": True, "internalType": "address", "name": "actor", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "name": "CustodyTransferred",
        "type": "event"
    }
]


class BlockchainManager:
    def __init__(self):
        self.w3 = None
        self.contract = None
        self.account = None
        self.private_key = PRIVATE_KEY
        self.signing_mode = None
        self.contract_address = None
        self._connected = False
        self._tx_lock = Lock()

    def _next_nonce(self, account):
        return self.w3.eth.get_transaction_count(account, "pending")

    def _fee_fields(self):
        """Build fee fields compatible with both legacy and EIP-1559 networks."""
        latest = self.w3.eth.get_block("latest")
        base_fee = latest.get("baseFeePerGas")

        if base_fee is None:
            return {"gasPrice": int(self.w3.eth.gas_price)}

        try:
            priority_fee = int(self.w3.eth.max_priority_fee)
        except Exception:
            # Safe default for testnets when RPC doesn't expose max_priority_fee.
            priority_fee = self.w3.to_wei(2, "gwei")

        max_fee = int(base_fee * 2 + priority_fee)
        return {
            "maxPriorityFeePerGas": priority_fee,
            "maxFeePerGas": max_fee,
        }

    def connect(self):
        try:
            self.w3 = Web3(Web3.HTTPProvider(RPC_URL))
            if geth_poa_middleware:
                try:
                    self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
                except Exception as e:
                    print(f"[Blockchain] Warning: Could not inject POA middleware: {e}. Continuing without it.")

            if not self.w3.is_connected():
                print("[Blockchain] WARNING: Cannot connect to the configured RPC endpoint. Running in offline mode.")
                return False

            # Prefer private-key signing for hosted RPCs, but allow local unlocked
            # accounts (Ganache/Hardhat/Anvil) when PRIVATE_KEY is not set.
            if self.private_key:
                self.account = self.w3.eth.account.from_key(self.private_key).address
                self.signing_mode = "private_key"
            else:
                try:
                    unlocked_accounts = self.w3.eth.accounts
                except Exception:
                    unlocked_accounts = []

                if not unlocked_accounts:
                    print(
                        "[Blockchain] WARNING: PRIVATE_KEY is not configured and no unlocked RPC accounts were found. "
                        "Running in offline mode."
                    )
                    return False

                self.account = unlocked_accounts[0]
                self.signing_mode = "node_unlocked"

            self._load_contract()
            self._connected = True
            print(f"[Blockchain] Connected to RPC endpoint at {RPC_URL}")
            print(f"[Blockchain] Using account: {self.account}")
            print(f"[Blockchain] Signing mode: {self.signing_mode}")
            return True
        except Exception as e:
            print(f"[Blockchain] Connection error: {e}")
            return False

    def _load_contract(self):
        # Prefer the deployed environment value first so Render can override a stale file.
        address = DEFAULT_CONTRACT_ADDRESS.strip()
        if not address and os.path.exists(CONTRACT_ADDRESS_FILE):
            with open(CONTRACT_ADDRESS_FILE) as f:
                address = f.read().strip()

        if address:
            checksum = Web3.to_checksum_address(address)
            try:
                code = self.w3.eth.get_code(checksum)
                if not code or len(code) == 0:
                    self.contract = None
                    self.contract_address = address
                    print(
                        f"[Blockchain] WARNING: Address {address} has no bytecode on current network "
                        f"(chain_id={self.w3.eth.chain_id}). Contract not loaded."
                    )
                    return
            except Exception as e:
                self.contract = None
                self.contract_address = address
                print(f"[Blockchain] WARNING: Could not verify contract bytecode at {address}: {e}")
                return

            self.contract_address = address
            abi = CONTRACT_ABI
            if os.path.exists(ABI_FILE):
                try:
                    import json
                    with open(ABI_FILE, "r", encoding="utf-8") as af:
                        abi = json.load(af)
                except Exception as ex:
                    print(f"[Blockchain] WARNING: Failed to load ABI from {ABI_FILE}: {ex}")

            self.contract = self.w3.eth.contract(
                address=checksum,
                abi=abi
            )
            print(f"[Blockchain] Contract loaded at {address}")

    def _sign_and_send(self, tx):
        if self.signing_mode == "private_key":
            signed_tx = self.w3.eth.account.sign_transaction(tx, private_key=self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        else:
            tx_hash = self.w3.eth.send_transaction(tx)
        try:
            return self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=TX_RECEIPT_TIMEOUT_SEC)
        except Exception as e:
            raise RuntimeError(
                f"Transaction {tx_hash.hex()} was not confirmed within {TX_RECEIPT_TIMEOUT_SEC} seconds: {e}"
            )

    def _receipt_to_tx_meta(self, receipt):
        tx_hash = receipt.transactionHash.hex()
        block_number = receipt.blockNumber
        block_ts = None
        try:
            block = self.w3.eth.get_block(block_number)
            block_ts = int(block.timestamp)
        except Exception:
            block_ts = None

        return {
            "tx_hash": tx_hash,
            "block_number": block_number,
            "timestamp": block_ts,
            "status": "confirmed" if getattr(receipt, "status", 0) == 1 else "failed",
        }

    def deploy_contract(self):
        """Deploy contract to the configured network. Returns contract address."""
        if not self.w3 or not self.w3.is_connected():
            return None, "Not connected to blockchain"

        try:
            bytecode = self._get_bytecode()
            if not bytecode:
                return None, "Bytecode not available. Compile Evidence.sol first."

            contract = self.w3.eth.contract(abi=CONTRACT_ABI, bytecode=bytecode)
            with self._tx_lock:
                nonce = self._next_nonce(self.account)
                tx = contract.constructor().build_transaction({
                    "from": self.account,
                    "nonce": nonce,
                    "gas": 3000000,
                    "chainId": self.w3.eth.chain_id,
                    **self._fee_fields(),
                })
                receipt = self._sign_and_send(tx)

            self.contract_address = receipt.contractAddress
            self.contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=CONTRACT_ABI
            )

            with open(CONTRACT_ADDRESS_FILE, "w") as f:
                f.write(self.contract_address)

            print(f"[Blockchain] Contract deployed at {self.contract_address}")
            return self.contract_address, None
        except Exception as e:
            return None, str(e)

    def _get_bytecode(self):
        """Try to compile Evidence.sol with solcx if available."""
        try:
            import solcx
            solcx.install_solc("0.8.0")
            sol_file = os.path.join(
                os.path.dirname(__file__), "..", "contracts", "Evidence.sol"
            )
            with open(sol_file) as f:
                source = f.read()
            compiled = solcx.compile_source(
                source,
                output_values=["abi", "bin"],
                solc_version="0.8.0"
            )
            key = list(compiled.keys())[0]
            return compiled[key]["bin"]
        except Exception as e:
            print(f"[Blockchain] Could not compile contract: {e}")
            return None

    def set_contract_address(self, address):
        """Manually set deployed contract address."""
        try:
            if not self.w3:
                return False
            self.contract_address = address
            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(address),
                abi=CONTRACT_ABI
            )
            with open(CONTRACT_ADDRESS_FILE, "w") as f:
                f.write(address)
            return True
        except Exception as e:
            print(f"[Blockchain] Set address error: {e}")
            return False

    def add_evidence(self, evidence_id, file_hash, file_name, case_id, from_account=None):
        if not self._connected or not self.contract:
            return None, ERR_BLOCKCHAIN_NOT_READY
        try:
            acct = from_account or self.account
            with self._tx_lock:
                nonce = self._next_nonce(acct)
                tx = self.contract.functions.addEvidence(
                    evidence_id, file_hash, file_name, case_id
                ).build_transaction({
                    "from": acct,
                    "nonce": nonce,
                    "gas": 500000,
                    "chainId": self.w3.eth.chain_id,
                    **self._fee_fields(),
                })
                receipt = self._sign_and_send(tx)
            return self._receipt_to_tx_meta(receipt), None
        except Exception as e:
            return None, str(e)

    def transfer_evidence(self, evidence_id, action, note, from_account=None):
        if not self._connected or not self.contract:
            return None, ERR_BLOCKCHAIN_NOT_READY
        try:
            acct = from_account or self.account
            with self._tx_lock:
                nonce = self._next_nonce(acct)
                tx = self.contract.functions.transferEvidence(
                    evidence_id, action, note
                ).build_transaction({
                    "from": acct,
                    "nonce": nonce,
                    "gas": 300000,
                    "chainId": self.w3.eth.chain_id,
                    **self._fee_fields(),
                })
                receipt = self._sign_and_send(tx)
            return self._receipt_to_tx_meta(receipt), None
        except Exception as e:
            return None, str(e)

    def evidence_exists(self, evidence_id):
        if not self._connected or not self.contract:
            return False, ERR_BLOCKCHAIN_NOT_READY
        try:
            exists = self.contract.functions.evidenceExists(evidence_id).call()
            return exists, None
        except Exception as e:
            return False, str(e)

    def record_custody_action(self, evidence_id, action, actor_name="", actor_role="", note="", case_id="", from_account=None):
        """Records a lifecycle custody action on-chain with structured metadata."""
        meta_parts = []
        if actor_name:
            role_str = f" ({actor_role})" if actor_role else ""
            meta_parts.append(f"Actor: {actor_name}{role_str}")
        if case_id:
            meta_parts.append(f"Case: {case_id}")
        if note:
            meta_parts.append(note)
        formatted_note = " | ".join(meta_parts) if meta_parts else action
        if len(formatted_note) > 300:
            formatted_note = formatted_note[:297] + "..."
        return self.transfer_evidence(evidence_id, action, formatted_note, from_account=from_account)

    def get_transaction_info(self, tx_hash):
        if not tx_hash:
            return None, "Missing transaction hash"
        if tx_hash.startswith("OFFLINE-"):
            return {
                "tx_hash": tx_hash,
                "block_number": None,
                "timestamp": None,
                "status": "offline",
                "source": "fallback",
            }, None
        if not self._connected or not self.w3:
            return None, "Blockchain not connected"

        try:
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            meta = self._receipt_to_tx_meta(receipt)
            meta["source"] = "blockchain"
            return meta, None
        except Exception as e:
            return None, str(e)

    def get_evidence(self, evidence_id):
        if not self._connected or not self.contract:
            return None, ERR_BLOCKCHAIN_NOT_READY
        try:
            result = self.contract.functions.getEvidence(evidence_id).call()
            return {
                "fileHash": result[0],
                "fileName": result[1],
                "caseId": result[2],
                "owner": result[3],
                "timestamp": result[4]
            }, None
        except Exception as e:
            return None, str(e)

    def get_custody_chain(self, evidence_id):
        if not self._connected or not self.contract:
            return [], "Blockchain not connected"
        try:
            count = self.contract.functions.getCustodyCount(evidence_id).call()
            records = []
            for i in range(count):
                r = self.contract.functions.getCustodyRecord(evidence_id, i).call()
                records.append({
                    "action": r[0],
                    "actor": r[1],
                    "note": r[2],
                    "timestamp": r[3]
                })
            return records, None
        except Exception as e:
            return [], str(e)

    def verify_evidence(self, evidence_id, current_hash):
        """Compare current file hash against blockchain stored hash."""
        if not self._connected or not self.contract:
            return None, ERR_BLOCKCHAIN_NOT_READY
        try:
            data, err = self.get_evidence(evidence_id)
            if err:
                return None, err
            stored_hash = data["fileHash"]
            intact = (stored_hash.lower() == current_hash.lower())
            return {
                "intact": intact,
                "stored_hash": stored_hash,
                "current_hash": current_hash,
                "evidence_id": evidence_id
            }, None
        except Exception as e:
            return None, str(e)

    # ── Feature 1: Merkle Tree Batching ──────────────────────────────────
    def commit_merkle_batch(self, root_hex, item_count, case_id):
        if not self._connected or not self.contract:
            return None, ERR_BLOCKCHAIN_NOT_READY
        try:
            root_bytes32 = bytes.fromhex(root_hex[2:] if root_hex.startswith("0x") else root_hex)
            if self.private_key and self.account:
                tx_data = self.contract.functions.commitMerkleBatch(
                    root_bytes32, item_count, case_id
                ).build_transaction({
                    "from": self.account,
                    "nonce": self._next_nonce(self.account),
                    "gas": 300000,
                    **self._fee_fields(),
                })
                signed = self.w3.eth.account.sign_transaction(tx_data, self.private_key)
                tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            else:
                tx_hash = self.contract.functions.commitMerkleBatch(
                    root_bytes32, item_count, case_id
                ).transact({"from": self.account})

            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=TX_RECEIPT_TIMEOUT_SEC)
            meta = self._receipt_to_tx_meta(receipt)
            meta["root_hex"] = root_hex
            meta["item_count"] = item_count
            meta["case_id"] = case_id
            return meta, None
        except Exception as e:
            return None, str(e)

    def verify_merkle_proof(self, leaf_hex, proof_list, root_hex):
        if not self._connected or not self.contract:
            # Fallback to off-chain Python Merkle verification
            return MerkleTreeHelper.verify_proof_offchain(leaf_hex, proof_list, root_hex), None
        try:
            leaf_b32 = MerkleTreeHelper._to_bytes32(leaf_hex)
            root_b32 = MerkleTreeHelper._to_bytes32(root_hex)
            proof_b32 = [MerkleTreeHelper._to_bytes32(p) for p in proof_list]
            
            valid = self.contract.functions.verifyMerkleProof(leaf_b32, proof_b32, root_b32).call()
            return valid, None
        except Exception as e:
            # Fallback to off-chain check
            valid = MerkleTreeHelper.verify_proof_offchain(leaf_hex, proof_list, root_hex)
            return valid, None

    def get_merkle_batch(self, root_hex):
        if not self._connected or not self.contract:
            return None, ERR_BLOCKCHAIN_NOT_READY
        try:
            root_b32 = bytes.fromhex(root_hex[2:] if root_hex.startswith("0x") else root_hex)
            res = self.contract.functions.getMerkleBatch(root_b32).call()
            return {
                "item_count": res[0],
                "committer": res[1],
                "timestamp": res[2],
                "case_id": res[3],
                "root_hex": root_hex
            }, None
        except Exception as e:
            return None, str(e)

    # ── Feature 2: Expiring Smart Warrants ──────────────────────────────
    def register_warrant(self, warrant_number, case_id, duration_seconds):
        if not self._connected or not self.contract:
            return None, ERR_BLOCKCHAIN_NOT_READY
        try:
            if self.private_key and self.account:
                tx_data = self.contract.functions.registerWarrant(
                    warrant_number, case_id, duration_seconds
                ).build_transaction({
                    "from": self.account,
                    "nonce": self._next_nonce(self.account),
                    "gas": 300000,
                    **self._fee_fields(),
                })
                signed = self.w3.eth.account.sign_transaction(tx_data, self.private_key)
                tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            else:
                tx_hash = self.contract.functions.registerWarrant(
                    warrant_number, case_id, duration_seconds
                ).transact({"from": self.account})

            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=TX_RECEIPT_TIMEOUT_SEC)
            meta = self._receipt_to_tx_meta(receipt)
            meta["warrant_number"] = warrant_number
            meta["case_id"] = case_id
            meta["duration_seconds"] = duration_seconds
            return meta, None
        except Exception as e:
            return None, str(e)

    def is_warrant_valid(self, warrant_number):
        if not self._connected or not self.contract:
            # Operational fallback
            return True, None
        try:
            valid = self.contract.functions.isWarrantValid(warrant_number).call()
            return valid, None
        except Exception as e:
            return False, str(e)

    def extend_warrant(self, warrant_number, additional_seconds):
        if not self._connected or not self.contract:
            return None, ERR_BLOCKCHAIN_NOT_READY
        try:
            if self.private_key and self.account:
                tx_data = self.contract.functions.extendWarrant(
                    warrant_number, additional_seconds
                ).build_transaction({
                    "from": self.account,
                    "nonce": self._next_nonce(self.account),
                    "gas": 200000,
                    **self._fee_fields(),
                })
                signed = self.w3.eth.account.sign_transaction(tx_data, self.private_key)
                tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            else:
                tx_hash = self.contract.functions.extendWarrant(
                    warrant_number, additional_seconds
                ).transact({"from": self.account})

            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=TX_RECEIPT_TIMEOUT_SEC)
            meta = self._receipt_to_tx_meta(receipt)
            meta["warrant_number"] = warrant_number
            meta["additional_seconds"] = additional_seconds
            return meta, None
        except Exception as e:
            return None, str(e)

    def get_warrant(self, warrant_number):
        if not self._connected or not self.contract:
            return None, ERR_BLOCKCHAIN_NOT_READY
        try:
            res = self.contract.functions.getWarrant(warrant_number).call()
            return {
                "case_id": res[0],
                "issued_by": res[1],
                "valid_until": res[2],
                "active": res[3],
                "is_valid": res[4]
            }, None
        except Exception as e:
            return None, str(e)

    @property
    def is_connected(self):
        return self._connected

    def get_network_info(self):
        if not self._connected:
            return {"connected": False}
        return {
            "connected": True,
            "network_id": self.w3.eth.chain_id,
            "block_number": self.w3.eth.block_number,
            "account": self.account,
            "signing_mode": self.signing_mode,
            "contract_address": self.contract_address,
            "balance": str(self.w3.eth.get_balance(self.account)) if self.account else "0"
        }


# ── Python Merkle Tree Helper ────────────────────────────────────────────────
import hashlib

class MerkleTreeHelper:
    @staticmethod
    def _to_bytes32(data):
        if isinstance(data, bytes):
            if len(data) == 32:
                return data
            return bytes(Web3.keccak(data))
        if isinstance(data, str):
            clean = data.strip()
            if clean.startswith("0x"):
                clean = clean[2:]
            if len(clean) == 64:
                try:
                    return bytes.fromhex(clean)
                except ValueError:
                    pass
            return bytes(Web3.keccak(text=data))
        return bytes(Web3.keccak(text=str(data)))

    @classmethod
    def _hash_pair(cls, a_b32, b_b32):
        a = cls._to_bytes32(a_b32)
        b = cls._to_bytes32(b_b32)
        if a <= b:
            return bytes(Web3.keccak(a + b))
        else:
            return bytes(Web3.keccak(b + a))

    @classmethod
    def build_tree(cls, items_list):
        if not items_list:
            empty_hex = "0x" + Web3.keccak(b"").hex()
            return empty_hex, {}, []

        leaves = [cls._to_bytes32(x) for x in items_list]
        tree = [leaves]

        while len(tree[-1]) > 1:
            layer = tree[-1]
            next_layer = []
            for i in range(0, len(layer), 2):
                left = layer[i]
                right = layer[i + 1] if i + 1 < len(layer) else left
                next_layer.append(cls._hash_pair(left, right))
            tree.append(next_layer)

        root_hex = "0x" + tree[-1][0].hex()
        proofs = {}

        for i, item in enumerate(items_list):
            proof = []
            idx = i
            for level in range(len(tree) - 1):
                layer = tree[level]
                is_right = (idx % 2 == 1)
                sibling_idx = idx - 1 if is_right else idx + 1
                if sibling_idx < len(layer):
                    proof.append("0x" + layer[sibling_idx].hex())
                else:
                    proof.append("0x" + layer[idx].hex())
                idx //= 2
            proofs[item] = proof

        return root_hex, proofs, ["0x" + l.hex() for l in leaves]

    @classmethod
    def verify_proof_offchain(cls, leaf_hex, proof_list, root_hex):
        computed = cls._to_bytes32(leaf_hex)
        target_root = cls._to_bytes32(root_hex)

        for p_str in proof_list:
            p_bytes = cls._to_bytes32(p_str)
            computed = cls._hash_pair(computed, p_bytes)

        return computed == target_root


# Singleton
BlockchainManager.MerkleTreeHelper = MerkleTreeHelper
blockchain = BlockchainManager()
blockchain.MerkleTreeHelper = MerkleTreeHelper
