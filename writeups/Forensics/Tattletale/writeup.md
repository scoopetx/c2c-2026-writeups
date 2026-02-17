# Log - Forensics

## Methodology
* **Vulnerability:** Compiled linux input event keylogger
* **Steps:**
    1.  Decompiled the `serizawa` binary with `pyinstxtractor.py` to reveal that it is a keylogger.
    2.  **Behaviour:** Captures raw keyboard events and stores in `cron.aseng`. The keylogger records every keystroke including backspaces, allowing full reconstruction of data entry.
    2.  **Password Reconstruction:** The user typed a password `4_g00d_fr13nD_in_n33d` which was recoverable by parsing their keystrokes.
    3.  Use the reconstructed password with OpenSSL AES-256-CBC to decrypt `whatisthis.enc`.
    4.  Convert the decrypted od (octal dump) output to binary to restore the flag!

## Reproducibility (Code/Commands)

# Parse keystrokes from `cron.aseng`

```python
import struct

# Standard Linux Input Event Codes (x86_64)
KEY_MAP = {
    2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    12: '-', 13: '=', 14: '[BACKSPACE]', 15: '[TAB]',
    16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p', 26: '[', 27: ']',
    30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l', 39: ';', 40: "'", 28: '[ENTER]',
    42: '[SHIFT]', 44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm', 51: ',', 52: '.', 53: '/', 57: ' ',
    54: '[SHIFT]', 29: '[CTRL]', 56: '[ALT]'
}

SHIFT_MAP = {
    '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
    '-': '_', '=': '+', ';': ':', "'": '"', ',': '<', '.': '>', '/': '?'
}

def decode(filename):
    try:
        with open(filename, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: {filename} not found.")
        return

    text = []
    is_shift = False
    
    # 24-byte chunks (struct input_event: 8s 8s 2s 2s 4s on 64-bit)
    for i in range(0, len(data), 24):
        chunk = data[i:i+24]
        if len(chunk) < 24: break
        
        # Unpack: time(16 bytes), type(H), code(H), value(i)
        _, type_, code, value = struct.unpack('16sHHi', chunk)
        
        # type 1 = EV_KEY
        if type_ == 1:
            if code in KEY_MAP:
                key = KEY_MAP[code]
                
                # Handle Shift state
                if key == '[SHIFT]':
                    # 1 = Press, 0 = Release
                    is_shift = (value == 1 or value == 2)
                
                # Process keys on Press (1) or Repeat (2)
                elif value in [1, 2]:
                    if key == '[BACKSPACE]':
                        if text: text.pop()
                    elif key == '[ENTER]':
                        text.append('\n')
                    elif key == '[TAB]':
                        text.append('\t')
                    elif len(key) == 1: # Printable char
                        char = key
                        if is_shift:
                            if char.isalpha(): 
                                char = char.upper()
                            elif char in SHIFT_MAP: 
                                char = SHIFT_MAP[char]
                        text.append(char)

    print("--- Extracted Keystrokes ---")
    print("".join(text))
    print("----------------------------")

if __name__ == "__main__":
    decode('cron.aseng')
```

# Parse flag from od

```bash
python3 - << 'PY'
> b = open('out_le.bin','rb').read()
> i=b.find(b'C2C{')
> if i==-1:
>     print('not found')
> else:
>     j=b.find(b'}',i)
>     seg=b[i:j+1]
>     filtered = bytes([c for c in seg if 32<=c<127])
>     print(filtered.decode('utf-8'))
> PY
C2C{it_is_just_4_very_s1mpl3_l1nuX_k3ylogger_xixixi_haiyaaaaa_ez}
```

## AI Usage

* **Did you use AI?** Minimal usage - Gemini 3 Pro used to create boilerplate linux keystroke `cron.aseng` parsing utility for speed.

## 🚩 Proof

**Flag:** C2C{it_is_just_4_very_s1mpl3_l1nuX_k3ylogger_xixixi_haiyaaaaa_ez}