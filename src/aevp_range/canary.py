"""128-bit canary tokens. Uniqueness is what converts a probabilistic agent
behaviour into a deterministic detection: a token has no benign path to any
sink, so observing it anywhere is proof the intended-malicious path executed.

Collision probability for a specific benign run producing a given token is
~2^-128; negligible across any realistic campaign.
"""
import json
import os
import secrets
from typing import Optional

from .paths import _ROOT

_REGISTRY = os.path.join(_ROOT, "canaries.json")


def _load() -> dict:
    if not os.path.exists(_REGISTRY):
        return {}
    try:
        with open(_REGISTRY, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(reg: dict) -> None:
    os.makedirs(_ROOT, exist_ok=True)
    with open(_REGISTRY, "w", encoding="utf-8") as fh:
        json.dump(reg, fh)


def mint(run_id: str, purpose: str) -> str:
    """Mint a unique canary and register it. Purpose is descriptive only."""
    token = "AEVP-" + secrets.token_hex(16)  # 128 bits
    reg = _load()
    reg[token] = {"run_id": run_id, "purpose": purpose}
    _save(reg)
    return token


def lookup(token: str) -> Optional[dict]:
    return _load().get(token)


def find_in(blob: str) -> list[str]:
    """Return every known canary that appears as a substring of blob."""
    if not blob:
        return []
    reg = _load()
    return [tok for tok in reg if tok in blob]


def reset() -> None:
    if os.path.exists(_REGISTRY):
        os.remove(_REGISTRY)
