"""Lightweight trace recorder shaped to the OpenTelemetry GenAI semantic
conventions (gen_ai.* attribute names). Written as JSONL spans so the whole run
is auditable and deterministically replayable without re-calling the model.

This intentionally avoids pulling the full OTel SDK into the foundation; the
attribute shape maps 1:1 to the GenAI semconv and can be swapped for a real
OTLP exporter later without changing call sites.
"""
import json
import os
import time
from typing import Any

from .paths import TRACE_LOG


class Tracer:
    def __init__(self, run_id: str, system: str = "aevp-range") -> None:
        self.run_id = run_id
        self.system = system

    def _write(self, span: dict[str, Any]) -> None:
        span["run_id"] = self.run_id
        span["ts"] = time.time()
        os.makedirs(os.path.dirname(TRACE_LOG), exist_ok=True)
        with open(TRACE_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(span) + "\n")

    def tool_call(self, name: str, arguments: dict, result_text: str, is_error: bool) -> None:
        self._write({
            "gen_ai.system": self.system,
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": name,
            "gen_ai.tool.arguments": arguments,
            "gen_ai.tool.result": result_text[:2000],
            "error": is_error,
        })

    def agent_output(self, text: str) -> None:
        self._write({
            "gen_ai.system": self.system,
            "gen_ai.operation.name": "agent_output",
            "gen_ai.output.text": text,
        })
