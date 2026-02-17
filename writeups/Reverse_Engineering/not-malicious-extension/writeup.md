# not-malicious-extension - Reverse Engineering

## 📝 Methodology
* **Reversing:** Extracted the PyInstaller binary using `pyinstxtractor`. Analyzed `chall.pyc` (Python 3.11 bytecode) and the native module `c2cext.so`.
* **Vulnerability:** **Weak Custom Cipher (Cascading Dependency).** The application used a custom function `f2` where the output bytes depended sequentially on the key characters (e.g., Output Byte 0 only relied on Key Chars 0-3). This allowed us to break the key in small chunks via recursive brute-force rather than attacking the full keyspace.
* **Decryption:**
    1.  Recovered RSA primes ($p, q$) directly from `c2cext` exports.
    2.  Brute-forced the custom cipher chunks to recover the RSA ciphertext.
    3.  Decrypted RSA and reversed the final XOR layer.

## 💻 Reproducibility (Code/Commands)
```python
import c2cext  # Native module from challenge

# 1. Recover RSA Privkey from Native Exports
p = c2cext.x000O000000O00O0O000OO00O()
q = c2cext.x00OOO000OOOO00OOO000OO0O()
n = p * q
d = pow(65537, -1, (p - 1) * (q - 1))

# 2. Cascading Brute-Force for Custom Cipher (Concept)
# We solve 12-char hex chunks by checking dependency on output bytes
def solve_chunk(target_bytes, pt_key):
    # Recursive search: Byte 0 depends only on first 4 hex chars
    for i in range(0x10000):
        k_candidate = f"{i:04x}"
        # ... (Recursive step checking against c2cext.f2 output) ...
    return recovered_chunk

# 3. Final Decrypt
# recovered_hex = [result of brute force]
rsa_ct = int.from_bytes(bytes.fromhex(recovered_hex), 'big')
pt_int = pow(rsa_ct, d, n)
pt_bytes = pt_int.to_bytes((pt_int.bit_length() + 7) // 8, 'big')

# Reverse Wrapping XOR
xor_key = bytes.fromhex('37d5bc0538...1113') # Extracted from bytecode
flag = bytes(pt_bytes[i] ^ xor_key[i % 64] for i in range(len(pt_bytes)))
print(f"Flag: {flag.decode()}")
```

## 🤖 AI Usage

* **Did you use AI?** Yes, Claude Opus 4.6 was utilised to assist with decompiling and reverse engineering the ciphertext.

## 🚩 Proof

**Flag:** C2C{D0n'7_r0ll_y0Ur_0wN_pr0t3c7t10n_d5714190225e53466c7f804798419716}