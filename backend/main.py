"""
main.py — Password Security Analyzer API
In linea con le guidelines NIST SP 800-63B
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List

import blocklist
from function import compute_entropy, get_charset_size, estimate_crack_time

app = FastAPI(title="Password Security Analyzer API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Modelli Pydantic ─────────────────────────────────────────────────────────

class PasswordRequest(BaseModel):
    password: str


class CheckResult(BaseModel):
    id: str
    label: str
    description: str
    passed: bool
    score: float
    max_score: float
    nist_ref: str
    severity: str  # "critical" | "warning" | "info"


class AnalysisResult(BaseModel):
    password_length: int
    entropy_bits: float
    charset_size: int
    estimated_crack_time: str
    score: float
    max_score: float
    percentage: float
    level: str
    level_label: str
    checks: List[CheckResult]
    recommendations: List[str]


# ─── Logica di analisi ────────────────────────────────────────────────────────

def analyze_password(password: str) -> AnalysisResult:
    lower = password.lower()
    length = len(password)
    checks: List[CheckResult] = []

    # ── CHECK 1: Lunghezza minima (NIST §5.1.1.1) ────────────────────────────
    if length >= 20:
        len_score, len_passed = 3.0, True
        len_desc = f"Lunghezza {length} caratteri — eccellente (≥20 raccomandato)"
    elif length >= 15:
        len_score, len_passed = 2.5, True
        len_desc = f"Lunghezza {length} caratteri — ottima (≥15 consigliato da NIST)"
    elif length >= 8:
        len_score, len_passed = 1.5, True
        len_desc = f"Lunghezza {length} caratteri — accettabile (≥8 è il minimo NIST)"
    else:
        len_score, len_passed = 0.0, False
        len_desc = f"Lunghezza {length} caratteri — insufficiente (minimo NIST: 8)"

    checks.append(CheckResult(
        id="length", label="Lunghezza password",
        description=len_desc, passed=len_passed,
        score=len_score, max_score=3.0,
        nist_ref="NIST SP 800-63B §5.1.1.1", severity="critical",
    ))

    # ── CHECK 2: Password non compromessa (NIST §5.1.1.2) ───────────────────
    is_common = lower in blocklist.common_passwords()
    checks.append(CheckResult(
        id="not_compromised", label="Non è una password compromessa",
        description=(
            "Rilevata nella lista delle password comunemente violate (HIBP / NIST blocklist)"
            if is_common else
            "Non rilevata nelle liste di password compromesse note"
        ),
        passed=not is_common,
        score=0.0 if is_common else 3.0, max_score=3.0,
        nist_ref="NIST SP 800-63B §5.1.1.2", severity="critical",
    ))

    # ── CHECK 3: Nessun carattere ripetuto (NIST §5.1.1.2) ──────────────────
    import re
    has_repetition = bool(re.search(r"(.)\1{2,}", password))
    checks.append(CheckResult(
        id="no_repetition", label="Nessun carattere ripetuto consecutivo",
        description=(
            "Trovati caratteri ripetuti in sequenza (es: aaa, 111, !!!)"
            if has_repetition else
            "Nessuna sequenza di caratteri ripetuti rilevata"
        ),
        passed=not has_repetition,
        score=0.0 if has_repetition else 1.5, max_score=1.5,
        nist_ref="NIST SP 800-63B §5.1.1.2", severity="warning",
    ))

    # ── CHECK 4: Nessuna sequenza di tastiera (NIST §5.1.1.2) ───────────────
    has_walk = any(walk in lower for walk in blocklist.keyboard_walks())
    checks.append(CheckResult(
        id="no_keyboard_walk", label="Nessuna sequenza di tastiera",
        description=(
            "Rilevata una sequenza di tasti adiacenti (es: qwerty, asdf, 12345)"
            if has_walk else
            "Nessuna sequenza di tastiera rilevata"
        ),
        passed=not has_walk,
        score=0.0 if has_walk else 1.5, max_score=1.5,
        nist_ref="NIST SP 800-63B §5.1.1.2", severity="warning",
    ))

    # ── CHECK 5: Nessuna parola contestuale (NIST §5.1.1.2) ─────────────────
    has_contextual = any(word in lower for word in blocklist.contextual_words())
    checks.append(CheckResult(
        id="no_contextual", label="Nessuna parola contestuale",
        description=(
            "Contiene parole associate al sistema (password, login, admin...)"
            if has_contextual else
            "Nessuna parola contestuale rilevata"
        ),
        passed=not has_contextual,
        score=0.0 if has_contextual else 1.0, max_score=1.0,
        nist_ref="NIST SP 800-63B §5.1.1.2", severity="warning",
    ))

    # ── CHECK 6: Varietà di caratteri / entropia (NIST §5.1.1) ──────────────
    has_lower   = bool(re.search(r"[a-z]", password))
    has_upper   = bool(re.search(r"[A-Z]", password))
    has_digit   = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))
    char_types  = sum([has_lower, has_upper, has_digit, has_special])

    type_score = {1: 0.5, 2: 1.0, 3: 1.5, 4: 2.0}.get(char_types, 0)
    type_desc  = (
        f"{char_types}/4 categorie utilizzate "
        f"({'min' if has_lower else '–'}"
        f"{'|MAI' if has_upper else '|–'}"
        f"{'|123' if has_digit else '|–'}"
        f"{'|!@#' if has_special else '|–'})"
    )
    checks.append(CheckResult(
        id="char_variety", label="Varietà caratteri (entropia)",
        description=type_desc, passed=char_types >= 2,
        score=type_score, max_score=2.0,
        nist_ref="NIST SP 800-63B §5.1.1 (entropia stimata)", severity="info",
    ))

    # ── CHECK 7: Supporto Unicode (NIST §5.1.1.1) ───────────────────────────
    has_unicode = any(ord(c) > 127 for c in password)
    checks.append(CheckResult(
        id="unicode", label="Supporto Unicode (bonus)",
        description=(
            "Caratteri Unicode rilevati — massima espansione dell'entropia"
            if has_unicode else
            "Solo caratteri ASCII standard (Unicode supportato e consigliato)"
        ),
        passed=True,
        score=0.5 if has_unicode else 0.0, max_score=0.5,
        nist_ref="NIST SP 800-63B §5.1.1.1", severity="info",
    ))

    # ── Calcolo punteggio finale ─────────────────────────────────────────────
    total_score = sum(c.score for c in checks)
    max_score   = sum(c.max_score for c in checks)
    percentage  = round((total_score / max_score) * 100, 1)

    # Le password compromesse sono sempre classificate come CRITICHE
    if is_common:
        percentage = min(percentage, 10.0)

    if percentage < 20 or not len_passed:
        level, level_label = "critical", "CRITICA"
    elif percentage < 45:
        level, level_label = "weak", "DEBOLE"
    elif percentage < 65:
        level, level_label = "fair", "DISCRETA"
    elif percentage < 82:
        level, level_label = "good", "BUONA"
    else:
        level, level_label = "strong", "ECCELLENTE"

    # ── Raccomandazioni ──────────────────────────────────────────────────────
    recs = []
    if not len_passed:
        recs.append("Usa almeno 8 caratteri (NIST richiede min. 8, consigliati ≥15)")
    elif length < 15:
        recs.append("Aumenta la lunghezza a ≥15 caratteri per maggiore sicurezza")
    if is_common:
        recs.append("Sostituisci con una password mai usata in precedenza")
    if has_repetition:
        recs.append("Evita sequenze di caratteri ripetuti (aaa, 111...)")
    if has_walk:
        recs.append("Evita sequenze di tastiera (qwerty, asdf, 12345...)")
    if has_contextual:
        recs.append("Evita parole come 'password', 'login', 'admin'")
    if char_types < 3:
        recs.append("Aggiungi maiuscole, numeri o caratteri speciali per aumentare l'entropia")
    if not recs:
        recs.append("Ottimo lavoro! Questa password soddisfa i criteri NIST SP 800-63B")

    entropy = compute_entropy(password)
    charset = get_charset_size(password)
    crack_time = estimate_crack_time(password, charset)

    return AnalysisResult(
        password_length=length,
        entropy_bits=entropy,
        charset_size=charset,
        estimated_crack_time=crack_time,
        score=round(total_score, 2),
        max_score=round(max_score, 2),
        percentage=percentage,
        level=level,
        level_label=level_label,
        checks=checks,
        recommendations=recs,
    )


# ─── Route ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"service": "Password Analyzer API", "standard": "NIST SP 800-63B"}


@app.post("/analyze", response_model=AnalysisResult)
def analyze(req: PasswordRequest):
    return analyze_password(req.password)


@app.get("/health")
def health():
    return {"status": "ok"}