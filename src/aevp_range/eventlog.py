"""Append-only JSONL event bus. This is the substrate every oracle reads.

An event is proof-relevant ground truth emitted by instrumentation the moment a
proof-relevant thing happens (a sink receives a request, a honeytoken is read, a
shadow tool is invoked, a capability contract is violated, a schema hash drifts).
No LLM writes here.
"""
import json
import os
import time
from typing import Any

from .paths import EVENT_LOG


def emit(kind: str, source: str, run_id: str, **data: Any) -> None:
    rec = {
        "ts": time.time(),
        "kind": kind,        # sinkhole | honeytoken | shadow_tool | capability | integrity | output
        "source": source,    # which component emitted it
        "run_id": run_id,    # the trial this belongs to
        "data": data,
    }
    os.makedirs(os.path.dirname(EVENT_LOG), exist_ok=True)
    with open(EVENT_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def read_all(run_id: str | None = None) -> list[dict]:
    if not os.path.exists(EVENT_LOG):
        return []
    out = []
    with open(EVENT_LOG, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if run_id is None or rec.get("run_id") == run_id:
                out.append(rec)
    return out


def reset() -> None:
    """Clear the event log (start-of-campaign hygiene)."""
    if os.path.exists(EVENT_LOG):
        os.remove(EVENT_LOG)
