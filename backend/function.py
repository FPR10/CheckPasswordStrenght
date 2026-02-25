"""
function.py — Funzioni di utilità per l'analisi della sicurezza delle password.

Contiene:
- compute_entropy    : entropia di Shannon in bit
- get_charset_size   : stima della dimensione del set di caratteri
- estimate_crack_time: tempo stimato per un attacco brute-force GPU
"""

import math
import re


def compute_entropy(password: str) -> float:
    """
    Calcola l'entropia di Shannon: H = -sum(p_i * log2(p_i)) * L
    dove p_i è la frequenza relativa di ciascun carattere e L la lunghezza.
    """
    if not password:
        return 0.0
    freq: dict = {}
    for char in password:
        freq[char] = freq.get(char, 0) + 1
    n = len(password)
    entropy = 0.0  # inizializzazione necessaria prima dell'accumulo
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy * n, 2)


def get_charset_size(password: str) -> int:
    """
    Stima la dimensione del set di caratteri effettivamente utilizzato,
    sommando i pool rilevati (minuscole, maiuscole, cifre, simboli, Unicode).
    """
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 33
    # Presenza di caratteri Unicode oltre l'ASCII standard
    if any(ord(c) > 127 for c in password):
        size += 128
    return max(size, 1)


def estimate_crack_time(password: str, charset_size: int) -> str:
    """
    Stima il tempo per un attacco brute-force assumendo 10 miliardi di guess/sec (GPU).
    Usa la formula: t = N^L / (2 * guesses_per_sec), dove N è il charset e L la lunghezza.
    """
    guesses_per_sec = 1e10
    combinations = charset_size ** len(password)
    seconds = combinations / (2 * guesses_per_sec)

    if seconds < 1:
        return "istantaneo"
    elif seconds < 60:
        return f"{int(seconds)} secondi"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minuti"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} ore"
    elif seconds < 365.25 * 86400:
        return f"{int(seconds / 86400)} giorni"
    elif seconds < 100 * 365.25 * 86400:
        return f"{int(seconds / (365.25 * 86400))} anni"
    elif seconds < 1e6 * 365.25 * 86400:
        return f"{int(seconds / (100 * 365.25 * 86400))} secoli"
    elif seconds < 1e9 * 365.25 * 86400:
        return f"{int(seconds / (1e6 * 365.25 * 86400))} milioni di anni"
    else:
        return "miliardi di anni"