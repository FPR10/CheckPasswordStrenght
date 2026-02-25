"""
Legge `nist_blocklist.json` una sola volta al primo accesso (lazy, lru_cache),
poi restituisce collezioni immutabili per lookup successivi a costo zero.

Per aggiornare i dati è sufficiente sostituire il file JSON (o ridefinire
BLOCKLIST_PATH verso un dataset più esteso) senza modificare la logica di analisi.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from itertools import chain

BLOCKLIST_PATH = Path(__file__).parent / "nist_blocklist.json"

'''
Il JSON viene letto una sola volta al primo accesso, poi rimane persistente in memoria per tutta la durata del processo
'''
@lru_cache(maxsize=1)
def _raw() -> dict:
    with BLOCKLIST_PATH.open(encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def common_passwords() -> frozenset[str]:
    """
    Restituisce un frozenset (case-insensitive) delle password compromesse note.
    Il frozenset garantisce lookup O(1) ed è immutabile e hashable.
    """
    entries: list[str] = _raw()["common_passwords"]
    return frozenset(p.lower() for p in entries)


@lru_cache(maxsize=1)
def keyboard_walks() -> tuple[str, ...]:
    """
    Restituisce una tupla piatta e deduplicata di tutte le sequenze di tastiera,
    ordinata dalla più lunga alla più corta: il primo match sarà sempre il più specifico.
    """
    walks_dict: dict = _raw()["keyboard_walks"]

    all_walks: list[str] = list(chain(
        *walks_dict["rows"].values(),
        walks_dict["diagonals"],
        walks_dict["numpad"],
    ))

    # Deduplicazione, normalizzazione in minuscolo, ordinamento dalla sequenza più lunga
    seen: set[str] = set()
    unique: list[str] = []
    for w in sorted((s.lower() for s in all_walks), key=len, reverse=True):
        if w not in seen:
            seen.add(w)
            unique.append(w)

    return tuple(unique)


@lru_cache(maxsize=1)
def contextual_words() -> tuple[str, ...]:
    """
    Restituisce una tupla piatta e deduplicata di tutti i termini legati al contesto
    di autenticazione (verbi di accesso, ruoli di sistema, frasi di benvenuto).
    """
    groups: dict = _raw()["contextual_words"]

    all_words: list[str] = list(chain(
        groups["authentication"],
        groups["roles"],
        groups["greetings"],
    ))

    seen: set[str] = set()
    unique: list[str] = []
    for w in (s.lower() for s in all_words):
        if w not in seen:
            seen.add(w)
            unique.append(w)

    return tuple(unique)