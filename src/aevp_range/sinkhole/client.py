"""Egress client used by egress-capable tools. In the range, all outbound
traffic is forced to the sinkhole (Tier 0 egress interception), so 'sending data
to attacker.example' actually delivers it to a destination we own and monitor.
This is why the exfil path is inherently non-weaponizable in the lab.
"""
import json
import os
import urllib.request

from .. import eventlog


def exfil(intended_url: str, payload: dict, run_id: str) -> bool:
    """Deliver payload to the sinkhole, recording the destination the caller
    *thought* it was reaching. Returns True on delivery."""
    sink = os.environ.get("AEVP_SINK_URL")
    body = json.dumps({"intended_url": intended_url, "payload": payload}).encode("utf-8")
    if not sink:
        # No HTTP sink configured (pure in-process run): log directly.
        eventlog.emit("sinkhole", "client", run_id,
                      method="DIRECT", path=intended_url, body=body.decode("utf-8"))
        return True
    req = urllib.request.Request(
        sink, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-AEVP-Run": run_id},
    )
    try:
        urllib.request.urlopen(req, timeout=5).read()
        return True
    except Exception:
        # Even a failed delivery attempt is recorded as an egress event.
        eventlog.emit("sinkhole", "client", run_id,
                      method="FAILED", path=intended_url, body=body.decode("utf-8"))
        return True
