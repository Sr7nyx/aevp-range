"""Offline end-to-end validation of the LIVE provider path.

Runs the fake OpenAI-compatible server in a background thread inside this
process, then executes a real campaign through OpenRouterProvider against it.
This exercises everything the real run exercises -- HTTP provider, strict
tool-calling message shape, budget accounting, fingerprint capture, oracles and
the negative control -- without needing network access or an API key.

    python -m tests.validate_live_path --n 15 --temperature 0.7
"""
import argparse
import asyncio
import os
import sys
import threading

from tests.fake_openai_server import serve

PORT = int(os.environ.get("AEVP_FAKE_PORT", "8099"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=15)
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--comply", type=float, default=0.5)
    ap.add_argument("--tier", choices=["blatant", "plausible", "subtle", "all"],
                    default="all")
    ap.add_argument("--fail-rate", type=float, default=0.0,
                    help="inject this fraction of 429s to test resilience")
    ap.add_argument("--api", choices=["openai", "anthropic"], default="openai")
    args = ap.parse_args()

    os.environ["AEVP_FAKE_COMPLY"] = str(args.comply)
    os.environ["AEVP_FAKE_FAIL_RATE"] = str(args.fail_rate)
    os.environ.setdefault("OPENROUTER_API_KEY", "fake-key-offline")

    httpd = serve(port=PORT)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    # Import after the env is set so the runner sees it.
    import run_range

    sys.argv = [
        "run_range.py",
        "--provider", "live",
        "--n", str(args.n),
        "--temperature", str(args.temperature),
        "--tier", args.tier,
        "--api", args.api,
        "--no-preflight",
        "--base-url", f"http://127.0.0.1:{PORT}",
        "--model", "fake/local-test",
    ]
    try:
        asyncio.run(run_range.main())
    finally:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
