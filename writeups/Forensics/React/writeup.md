# React - Forensics

_Side Note: This was my favourite challenge of the whole CTF, I deeply looked into TrevorC2 to understand the usage and thoroughly enjoyed it!_

## 📝 Methodology
* **Vulnerability:** React2Shell CVE-2025-55182 RCE exploit into C2 Agent
* **Overview:**
    1.  This challenge involved analysing `network.pcap`, a wireshark file.
    2.  An attacker had exploited the React2Shell vulnerability to deploy TrevorC2 agent onto the device. 
    3.  The attacker then executed various commands on the agent.
* **Steps:**
    1.  Analysed network traffic (`network.pcap`) and identified React2Shell packets and `nmap` probing attempts before exploitation.
    2.  Identified `a.py` uploaded onto the client. Further research revealed this was TrevorC2 agent file.
    3.  Filtering for `http.user_agent == "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"` I was able to isolate all C2 Traffic (TrevorC2 uses a specific, hardcoded User Agent)
    4.  The return data to the C2 server, e.g. `guid=TWc4ZEJROHVONWpJTC95UmhmcVNZejdSeWljOUNXYXpsMzkydWJ1RDEyUT0=` is encrypted and this key was recovered.
    5.  Decrypting the TrevorC2 communications revealed all commands sent and executed by the attacker such as adding private keys for `ssh` persistent access. 

## Submission Script

```python
import socket, re, time

HOST, PORT = 'challenges.1pc.tf', 45000
ANSWERS = {
    1: '192.168.56.104',                                            # Attacker IP
    2: '192.168.56.103',                                            # Victim IP
    3: 'nmap',                                                      # First tool
    4: 'CVE-2025-55182',                                            # CVE ID
    5: 'echo 123',                                                  # First command
    6: 'TrevorC2',                                                  # C2 framework
    7: 'aa34042ac9c17b459b93c0d49c7124ea',                          # Encryption key
    8: '/etc/passwd',                                               # First accessed file
    9: "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4L46b5SCsXlizakO+iXIr2pjQ48dryUiX1tCGbzEUZ kali@kali' > /home/daffainfo/.ssh/authorized_keys",  # Persistence
    10: 'T1098.004',                                               # MITRE ATT&CK technique
}

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    buf = ""
    while True:
        data = s.recv(1024).decode()
        print(data, end="")
        buf += data
        if "Your Answer:" in buf:
            q_num = int(re.findall(r'Question #(\d+)', buf)[-1])
            if q_num in ANSWERS:
                print(ANSWERS[q_num])
                s.sendall((ANSWERS[q_num] + "\n").encode())
                buf = ""
                time.sleep(0.5)
```

## AI Usage

* **Did you use AI?** Claude Opus 4.6 was given the task of decrypting TrevorC2 communications, however it failed and in the end I did it myself. So no useful AI Usage.

## 🚩 Proof

# Conversation
```md
Please answer the following questions based on your analysis:

Question #1:
1. What is the IP address of the attacker?
Required Format: 127.0.0.1
Your Answer: 192.168.56.104
Status: Correct!

Question #2:
2. What is the IP address of the victim?
Required Format: 127.0.0.1
Your Answer: 192.168.56.103
Status: Correct!

Question #3:
3. What tools did the attacker use first? (Lowercase)
Required Format: -
Your Answer: nmap
Status: Correct!

Question #4:
4. Which CVE ID was exploited by the attacker?
Required Format: CVE-XXXX-XXXX
Your Answer: CVE-2025-55182
Status: Correct!

Question #5:
5. What was the first command executed by the attacker?
Required Format: -
Your Answer: echo 123
Status: Correct!

Question #6:
6. Which Command and Control (C2) framework is being used?
Required Format: Cobalt Strike
Your Answer: TrevorC2
Status: Correct!

Question #7:
7. What encryption key / password was used to interact with the C2 server?
Required Format: -
Your Answer: aa34042ac9c17b459b93c0d49c7124ea
Status: Correct!

Question #8:
8. What was the first file accessed by the attacker?
Required Format: /file/to/path
Your Answer: /etc/passwd
Status: Correct!

Question #9:
9. What command or method was used by the attacker to establish persistence on the system?
Required Format: -
Your Answer: echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4L46b5SCsXlizakO+iXIr2pjQ48dryUiX1tCGbzEUZ kali@kali' > /home/daffainfo/.ssh/authorized_keys
Status: Correct!

Question #10:
10. Which MITRE ATT&CK technique corresponds to the persistence method used?
Required Format: T1337.000
Your Answer: T1098.004
Status: Correct!

========================================
Congratulations!
Flag: C2C{r34C725h3Ll_f0r_7H3_W1n_2f50e08155fb}
========================================
```

**Flag:** C2C{r34C725h3Ll_f0r_7H3_W1n_2f50e08155fb}