# Log - Forensics

## Methodology
* **Vulnerability:** SQL Injection in Easy Quotes WordPress Plugin (CVE-2025-26943)
* **Steps:**
    1.  This challenge involved analysing `access.log` and `error.log` to obtain answers to 10 forensic questions.
    2.  The attacker used SQL Injection in the Easy Quotes Plugin to gain access to personal information.
    3.  All answers were found by manually searching or using 'grep' to search the log files for keywords.

## AI Usage

* **Did you use AI?** No AI usage for this challenge.

## Submission Script

```python
import socket, re, time

HOST, PORT = 'challenges.1pc.tf', 22280
ANSWERS = {
    1: '182.8.97.244', 2: '219.75.27.16', 3: '6', 4: 'Easy Quotes',
    5: 'CVE-2025-26943', 6: 'sqlmap/1.10.1.21', 7: 'admin@daffainfo.com',
    8: '$wp$2y$10$vMTERqJh2IlhS.NZthNpRu/VWyhLWc0ZmTgbzIUcWxwNwXze44SqW',
    9: '11/01/2026 13:12:49'
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

## 🚩 Proof

# Conversation

```md
[*] Connecting to challenges.1pc.tf:35124...
Please answer the following questions based on your analysis:

Question #1:
1. What is the Victim's IP address?
Required Format: 127.0.0.1
Your Answer: 182.8.97.244
Status: Correct!

Question #2:
2. What is the Attacker's IP address?
Required Format: 127.0.0.1
Your Answer: 219.75.27.16
Status: Correct!

Question #3:
3. How many login attempts were made by the attacker?
Required Format: 1337
Your Answer: 6
Status: Correct!

Question #4:
4. Which plugin was affected (Full Name)?
Required Format: -
Your Answer: Easy Quotes
Status: Correct!

Question #5:
5. What is the CVE ID?
Required Format: CVE-XXXX-XXXX
Your Answer: CVE-2025-26943
Status: Correct!

Question #6:
6. Which tool and version were used to exploit the CVE?
Required Format: tool_name/13.3.7
Your Answer: sqlmap/1.10.1.21
Status: Correct!

Question #7:
7. What is the email address obtained by the attacker?
Required Format: r00t@localhost.xyz
Your Answer: admin@daffainfo.com
Status: Correct!

Question #8:
8. What is the password hash obtained by the attacker?
Required Format: -
Your Answer: $wp$2y$10$vMTERqJh2IlhS.NZthNpRu/VWyhLWc0ZmTgbzIUcWxwNwXze44SqW
Status: Correct!

Question #9:
9. When did the attacker successfully log in?
Required Format: DD/MM/YYYY HH:MM:SS
Your Answer: 11/01/2026 13:12:49
Status: Correct!

========================================
Congratulations!
Flag: C2C{7H15_15_V3rY_345Y_1b0dc2db094d}
========================================
```

**Flag:** C2C{7H15_15_V3rY_345Y_1b0dc2db094d}