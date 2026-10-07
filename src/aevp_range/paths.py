"""Shared runtime paths. Every process (runner, sinkhole, MCP server subprocess)
resolves the same files from env so they share one source of truth. In Docker
these live on a shared volume; locally they default under ./_runtime.
"""
import os

_ROOT = os.environ.get("AEVP_RUNTIME", os.path.join(os.getcwd(), "_runtime"))


def _p(env_key: str, default_name: str) -> str:
    val = os.environ.get(env_key)
    if val:
        return val
    os.makedirs(_ROOT, exist_ok=True)
    return os.path.join(_ROOT, default_name)


EVENT_LOG = _p("AEVP_EVENT_LOG", "events.jsonl")        # oracle substrate
TRACE_LOG = _p("AEVP_TRACE", "trace.jsonl")             # GenAI-shaped spans
MEMORY = _p("AEVP_MEMORY", "memory.json")               # cross-session store (ASI06)
SCHEMA_BASELINE = _p("AEVP_SCHEMA_BASELINE", "schema_baseline.json")  # P5 baseline
