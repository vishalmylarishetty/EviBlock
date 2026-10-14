"""
Deploy Evidence.sol to local Ganache and update .env + contract_address.txt
"""
import json
import os
import sys
import re
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

RPC_URL  = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
SOL_FILE = PROJECT_ROOT / "contracts" / "Evidence.sol"
ABI_OUT  = PROJECT_ROOT / "contracts" / "Evidence_abi.json"
ADDR_FILE = PROJECT_ROOT / "backend" / "contract_address.txt"
ENV_FILE  = PROJECT_ROOT / ".env"

print("=" * 60)
print("  ForensicChain — Contract Deployment Script")
print("=" * 60)

# 1. Connect to Ganache
print(f"\n[1/4] Connecting to Ganache at {RPC_URL} ...")
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print("ERROR: Cannot reach Ganache.")
    sys.exit(1)

accounts  = w3.eth.accounts
deployer  = accounts[0]
balance   = w3.from_wei(w3.eth.get_balance(deployer), "ether")
print(f"  Connected | chain_id={w3.eth.chain_id} | block={w3.eth.block_number}")
print(f"  Deployer : {deployer}  ({balance:.4f} ETH)")

# 2. Compile Evidence.sol
print("\n[2/4] Compiling Evidence.sol with py-solc-x ...")
try:
    import solcx
    target = "0.8.19"
    installed = [str(v) for v in solcx.get_installed_solc_versions()]
    if target not in installed:
        print(f"  Installing solc {target} ...")
        solcx.install_solc(target, show_progress=True)
    solcx.set_solc_version(target)

    with open(SOL_FILE, "r") as f:
        source = f.read()

    compiled = solcx.compile_source(
        source, output_values=["abi", "bin"], solc_version=target
    )
    key = [k for k in compiled if "EvidenceManagement" in k][0]
    abi      = compiled[key]["abi"]
    bytecode = compiled[key]["bin"]

    print(f"  Compiled | ABI functions: {len([x for x in abi if x.get('type')=='function'])}")
    with open(ABI_OUT, "w") as f:
        json.dump(abi, f, indent=2)
    print(f"  ABI saved to {ABI_OUT}")
except Exception as e:
    print(f"  ERROR: {e}")
    sys.exit(1)

# 3. Deploy
print("\n[3/4] Deploying contract ...")
try:
    contract  = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash   = contract.constructor().transact({"from": deployer, "gas": 6_000_000})
    receipt   = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    if receipt.status == 0:
        raise RuntimeError("Deployment failed with status 0")
    addr      = receipt.contractAddress
    print(f"  Deployed at : {addr}")
    print(f"  Tx hash     : {receipt.transactionHash.hex()}")
    print(f"  Gas used    : {receipt.gasUsed:,}")
except Exception as e:
    print(f"  ERROR: {e}")
    sys.exit(1)

# 4. Update config files
print("\n[4/4] Updating configuration ...")
ADDR_FILE.write_text(addr)
print(f"  Updated {ADDR_FILE}")

env_text = ENV_FILE.read_text(encoding="utf-8")
if re.search(r"^CONTRACT_ADDRESS=", env_text, re.MULTILINE):
    env_text = re.sub(r"^CONTRACT_ADDRESS=.*$", f"CONTRACT_ADDRESS={addr}", env_text, flags=re.MULTILINE)
else:
    env_text += f"\nCONTRACT_ADDRESS={addr}\n"
ENV_FILE.write_text(env_text, encoding="utf-8")
print(f"  Updated .env CONTRACT_ADDRESS={addr}")

print("\n" + "=" * 60)
print(f"  Deployment complete! Address: {addr}")
print("  Restart the Flask backend to pick up the new address.")
print("=" * 60)
