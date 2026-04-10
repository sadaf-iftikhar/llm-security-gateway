import re
import time
from collections import defaultdict
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from config import (
    INJECTION_THRESHOLD_BLOCK,
    INJECTION_THRESHOLD_MASK,
    MIN_CONFIDENCE,
    COMPOSITE_RISK_THRESHOLD,
    MAX_ATTEMPTS,
    TIME_WINDOW_SECONDS
)
from recognizers import get_custom_recognizers

# Presidio
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()
for recognizer in get_custom_recognizers():
    analyzer.registry.add_recognizer(recognizer)

# Rate limiting tracker
attempt_log = defaultdict(list)

# Attack phrases 
ATTACK_PHRASES = [
    # Prompt injection
    "ignore previous instructions",
    "ignore all instructions",
    "forget your rules",
    "forget everything above",
    "override your settings",
    # Jailbreak
    "jailbreak",
    "dan mode",
    "do anything now",
    "pretend you have no restrictions",
    # Role manipulation
    "act as admin",
    "pretend you are",
    "you are now",
    "roleplay as",
    # System prompt extraction
    "reveal system prompt",
    "show your instructions",
    "repeat everything above",
    "print your prompt",
    "what are your hidden rules",
    # Bypass tricks
    "bypass",
    "simulate developer mode",
    "maintenance mode",
]

def normalize(text: str) -> str:
    # Handles mixed case and extra spaces tricks
    text = text.lower()
    text = re.sub(r'\s+', ' ', text).strip()
    text = re.sub(r'[^\w\s@.+\-]', '', text)
    return text

def check_rate_limit(user_id: str) -> bool:
    now = time.time()
    # Keep only recent attempts within time window
    attempt_log[user_id] = [
        t for t in attempt_log[user_id]
        if now - t < TIME_WINDOW_SECONDS
    ]
    attempt_log[user_id].append(now)
    return len(attempt_log[user_id]) > MAX_ATTEMPTS

def get_injection_score(text: str):
    normalized = normalize(text)
    score = 0
    found = []
    for phrase in ATTACK_PHRASES:
        if phrase in normalized:
            score += 1
            found.append(phrase)
    return score, found

def scan_pii(text: str):
    raw_results = analyzer.analyze(text=text, language="en")

    # Confidence calibration: only keep results above threshold
    filtered = [r for r in raw_results if r.score >= MIN_CONFIDENCE]

    if not filtered:
        return False, text, [], "LOW"

    # Composite entity detection: count unique PII types
    pii_types = list(set([r.entity_type for r in filtered]))
    composite_count = len(pii_types)

    # Higher composite = higher risk level
    if composite_count >= COMPOSITE_RISK_THRESHOLD:
        composite_risk = "HIGH"
    else:
        composite_risk = "MEDIUM"

    masked = anonymizer.anonymize(text=text, analyzer_results=filtered)
    return True, masked.text, pii_types, composite_risk