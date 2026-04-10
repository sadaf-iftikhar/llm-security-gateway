# LLM Security Gateway
### CSC262 Artificial Intelligence | Lab Mid Assignment
**Instructor:** Tooba Tehreem | COMSATS University Islamabad, Wah Campus

---

## What This Project Does

Large Language Models can be tricked very easily. Someone 
can just type the right words and the model starts ignoring 
its rules, sharing secret information, or behaving in ways 
it should never behave. This project is a security gateway 
that sits between the user and the LLM and checks every 
single message before it goes through.

The gateway does three things. First it checks if the message 
contains any attack patterns like prompt injection or jailbreak 
phrases. Second it scans the message for sensitive personal 
information like Pakistani phone numbers, CNIC numbers, API 
keys, and email addresses using Microsoft Presidio. Third it 
makes a policy decision based on what it found. The message 
is either allowed through as it is, returned with sensitive 
parts masked and hidden, or blocked completely.

If someone keeps sending suspicious messages repeatedly they 
get temporarily blocked for 60 seconds after 5 attempts.

---

## Attack Types This System Handles

- Prompt Injection
- Jailbreak Attack
- System Prompt Extraction
- Sensitive Information Leakage
- Obfuscation Attack using mixed case and extra spaces

---

## Project Structure
llm-security-gateway/
│
├── config.py         # All thresholds and settings in one place
├── recognizers.py    # Custom Presidio detectors for Pakistani formats
├── detector.py       # Injection scoring, PII scanning, rate limiting
└── main.py           # FastAPI server and policy decision logic
