from fastapi import FastAPI
from pydantic import BaseModel
import time
from detector import (
    check_rate_limit,
    get_injection_score,
    scan_pii
)
from config import (
    INJECTION_THRESHOLD_BLOCK,
    INJECTION_THRESHOLD_MASK
)
app = FastAPI(title="LLM Security Gateway")

class UserMessage(BaseModel):
    user_id: str = "anonymous"
    text: str
@app.get("/")
def home():
    return {"status": "LLM Security Gateway Running"}

@app.post("/analyze")
def analyze(message: UserMessage):
    start = time.time()

    # check the rate limit
    if check_rate_limit(message.user_id):
        return {
            "user_id":   message.user_id,
            "decision":  "BLOCKED",
            "reason":    "Too many attempts. Wait 60 seconds.",
            "latency_ms": 0
        }
        
    # Injection detection
    inj_score, inj_phrases = get_injection_score(message.text)

    # scan PII
    has_pii, masked_text, pii_types, composite_risk = scan_pii(message.text)

    #Policy DECISIONS
    if inj_score >= INJECTION_THRESHOLD_BLOCK:
        decision = "BLOCK"
        output   = "[BLOCKED — Attack Detected]"
        reason   = f"Injection score {inj_score}. Found: {inj_phrases}"

    elif inj_score >= INJECTION_THRESHOLD_MASK or has_pii:
        decision = "MASK"
        output   = masked_text
        reason   = (f"PII types: {pii_types}, "
                    f"Composite risk: {composite_risk}"
                    if has_pii
                    else f"Suspicious phrase: {inj_phrases}")
    else:
        decision = "ALLOW"
        output   = message.text
        reason   = "Input is safe"

    latency = round((time.time() - start) * 1000, 2)

    #results
    return {
        "user_id":          message.user_id,
        "original_input":   message.text,
        "decision":         decision,
        "reason":           reason,
        "safe_output":      output,
        "injection_score":  inj_score,
        "pii_detected":     has_pii,
        "pii_types":        pii_types,
        "composite_risk":   composite_risk,
        "latency_ms":       latency
    }
