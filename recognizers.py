from presidio_analyzer import PatternRecognizer, Pattern

def get_custom_recognizers():

    pak_phone = PatternRecognizer(
        supported_entity="PAK_PHONE",
        patterns=[
            Pattern("PAK_LOCAL",  r"0[3][0-9]{2}[-\s]?[0-9]{7}", 0.85),
            Pattern("PAK_INTL",   r"\+92[3][0-9]{9}",             0.90),
        ],
        context=["call", "contact", "number","phone", "whatsapp", "mobile"]  
    )

    api_key = PatternRecognizer(
        supported_entity="API_KEY",
        patterns=[
            Pattern("SK_KEY",     r"sk-[a-zA-Z0-9]{20,}",         0.90),
            Pattern("BEARER",     r"Bearer\s[a-zA-Z0-9\-._~+/]+=*", 0.88),
        ],
        context=["key", "token", "secret","authorization", "api", "bearer"]  
    )
  
    cnic = PatternRecognizer(
        supported_entity="PAK_CNIC",
        patterns=[
            Pattern("CNIC", r"[0-9]{5}-[0-9]{7}-[0-9]{1}", 0.95),
        ],
        context=["cnic", "identity", "id card","national", "nadra"] 
    )

    internal_id = PatternRecognizer(
        supported_entity="INTERNAL_ID",
        patterns=[
            Pattern("EMP_ID", r"EMP-[0-9]{4,6}",   0.80),
            Pattern("STU_ID", r"STU-[0-9]{4,6}",   0.80),
            Pattern("CUI_ID", r"SP[0-9]{2}-[A-Z]{3}-[0-9]{3}", 0.85),
        ],
        context=["employee", "student", "id","registration", "roll"]  
    )
    return [pak_phone, api_key, cnic, internal_id]
