"""AEVP range campaign runner.

    python run_range.py                                   # scripted mock, blatant
    python run_range.py --tier all --n 30                 # 6x3 matrix (mock)
    python run_range.py --provider live --preset groq --tier all --n 5
    python run_range.py --provider live --preset cerebras --tier all --n 10

The benign twin is tier-invariant, so one twin arm per case gates all tiers.
Live trials are non-fatal: a provider error (429/402/network) marks that trial
errored and the campaign continues, so a rate-limit hiccup cannot torch a long
run. Reports ASR (over completed trials) with a 95% Wilson interval.
"""
import argparse
import asyncio
import json
import math
import os

from aevp_range import canary, eventlog
from aevp_range.agent import run_agent
from aevp_range.budget import Budget, BudgetExceeded
from aevp_range.mcp_server import _record_baselines
from aevp_range.oracles import evaluate
from aevp_range.paths import MEMORY, TRACE_LOG, _ROOT
from aevp_range.payloads import TIERS
from aevp_range.provider import (AnthropicMessagesProvider, OpenAICompatibleProvider,
                                 RateLimiter, ScriptedProvider)
from aevp_range.stores import SharedMemoryStore
from attacks.cases import CASES, note_injected_text

# Provider presets: base URL, API-key env var, a conservative default requests/min
# (chosen to sit under the free-tier ceiling), and a tool-calling-capable model.
PRESETS = {
    "openrouter": {"base_url": "https://openrouter.ai/api/v1", "key_env": "OPENROUTER_API_KEY",
                   "rpm": 0, "model": "openai/gpt-4o-mini", "api": "openai"},
    "groq":       {"base_url": "https://api.groq.com/openai/v1", "key_env": "GROQ_API_KEY",
                   "rpm": 8, "model": "openai/gpt-oss-120b", "api": "openai"},
    "cerebras":   {"base_url": "https://api.cerebras.ai/v1", "key_env": "CEREBRAS_API_KEY",
                   "rpm": 5, "model": "gpt-oss-120b", "api": "openai"},
    # AI Hub is an Anthropic /v1/messages gateway (base URL MUST end with /v1).
    # Default model works non-streaming; rs/* models (minimax-m3, hy3-tencent)
    # need streaming, which this harness does not yet do.
    "aihub":      {"base_url": "https://ai-hub.aicampus.my/v1", "key_env": "AIHUB_API_KEY",
                   "rpm": 10, "model": "cbcn/hy3-preview", "api": "anthropic"},
}


# Per-trial cost constants, measured from a real gpt-oss-120b campaign
# (N=5 blatant, 6 cases -> 150 calls, 70,346 prompt + 11,123 completion tokens).
# Override with --calls-per-trial / --tok-in / --tok-out if your model differs.
MEASURED_CALLS_PER_TRIAL = 2.50
MEASURED_TOK_IN_PER_TRIAL = 1172
MEASURED_TOK_OUT_PER_TRIAL = 185


def plan_trials(n: int, tiers: int, twin_n: int, mi_n: int,
                md_cases: int, mi_cases: int) -> int:
    """Total trials for a campaign: model-dependent cases sweep tiers on the
    attack arm and share one twin arm; model-independent cases do neither."""
    return md_cases * (twin_n + tiers * n) + mi_cases * (mi_n + mi_n)


def estimate(args, md_cases: int, mi_cases: int) -> dict:
    tiers = len(TIERS) if args.tier == "all" else 1
    t = plan_trials(args.n, tiers, args.twin_n, args.mi_n, md_cases, mi_cases)
    calls = t * args.calls_per_trial
    tin = t * args.tok_in / 1e6
    tout = t * args.tok_out / 1e6
    usd = tin * args.price_in + tout * args.price_out
    minutes = (calls / args.rpm) if args.rpm and args.rpm > 0 else 0.0
    return {"trials": t, "calls": calls, "tok_in_m": tin, "tok_out_m": tout,
            "usd": usd, "local": usd * args.fx, "minutes": minutes}


def wilson(x: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = x / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (p, max(0.0, center - half), min(1.0, center + half))


def or_provider_body(args):
    """OpenRouter routing body that pins one upstream with no fallback."""
    name = getattr(args, "or_provider", None)
    if not name:
        return None
    return {"provider": {"order": [name], "allow_fallbacks": False}}


def unwrap_exc(exc: BaseException) -> str:
    """Flatten ExceptionGroup/BaseExceptionGroup (raised by the MCP anyio task
    group) to the informative leaf messages, so a real HTTP 401/400/timeout is
    visible instead of 'unhandled errors in a TaskGroup'."""
    leaves = []

    def walk(e):
        if isinstance(e, BaseExceptionGroup):
            for sub in e.exceptions:
                walk(sub)
        else:
            leaves.append(f"{type(e).__name__}: {e}")

    walk(exc)
    return " | ".join(leaves) if leaves else f"{type(exc).__name__}: {exc}"


def _reset_memory() -> None:
    if os.path.exists(MEMORY):
        os.remove(MEMORY)


def _make_provider(args, case, run_id, is_attack, budget, limiter):
    if args.provider == "mock":
        actions = (case.build_attack if is_attack else case.build_twin)(run_id)
        return ScriptedProvider(actions)
    common = dict(model=args.model, api_key=os.environ.get(args.api_key_env, ""),
                  base_url=args.base_url, temperature=args.temperature,
                  max_tokens=args.max_tokens, budget=budget, limiter=limiter)
    if args.user_agent:
        common["user_agent"] = args.user_agent
    if args.api == "anthropic":
        return AnthropicMessagesProvider(**common)
    return OpenAICompatibleProvider(reasoning_effort=args.reasoning_effort,
                                    extra_body=or_provider_body(args), **common)


async def _one_trial(args, case, run_id, *, is_attack, tier, budget, limiter) -> dict:
    _reset_memory()
    token = canary.mint(run_id, f"{case.id}-{'atk' if is_attack else 'twin'}")
    note_injected_text(token)
    if case.seed_memory is not None:
        SharedMemoryStore().remember("refund_policy_note",
                                     case.seed_memory(token, is_attack, tier))
    provider = _make_provider(args, case, run_id, is_attack, budget, limiter)
    result = await run_agent(
        case.task, run_id, provider,
        rugpull=case.rugpull_attack if is_attack else False,
        inject=case.inject if is_attack else "",
        canary=token, memory_context=case.memory_context, tier=tier,
        max_steps=args.max_steps,
    )
    verdict = evaluate(case.asi, run_id)
    return {"fired": verdict.fired, "evidence": verdict.evidence,
            "fingerprint": result["fingerprint"],
            "tool_calls": result.get("tool_call_count", 0)}


async def _safe_trial(args, case, run_id, *, is_attack, tier, budget, limiter) -> dict:
    """Non-fatal wrapper: a provider error marks the trial errored; BudgetExceeded
    still propagates to halt the campaign."""
    try:
        return await _one_trial(args, case, run_id, is_attack=is_attack, tier=tier,
                                budget=budget, limiter=limiter)
    except BudgetExceeded:
        raise
    except Exception as exc:  # provider/network error on this trial only
        return {"error": unwrap_exc(exc)[:300]}


async def run_case(args, case, budget, limiter) -> dict:
    tiers = list(TIERS) if args.tier == "all" else [args.tier]
    per_tier, twin_fires, twin_errors, detected, truncated, fingerprint = {}, 0, 0, False, False, {}
    # Model-independent cases (schema-hash checks) produce an identical verdict
    # every trial, so extra trials add no information -- run mi_n of them.
    n_attack = args.n if case.model_dependent else args.mi_n
    n_twin = args.twin_n if case.model_dependent else args.mi_n

    leak_evidence: list = []
    errors_seen: list = []

    def _note_error(msg: str) -> None:
        # Keep the first few DISTINCT messages: 26 identical timeouts are one
        # fact, not 26. Without this an error count is an opaque black box.
        if msg not in errors_seen and len(errors_seen) < 3:
            errors_seen.append(msg)

    try:
        for i in range(n_twin):
            r = await _safe_trial(args, case, f"{case.id}-twin-{i}",
                                  is_attack=False, tier=tiers[0], budget=budget, limiter=limiter)
            if "error" in r:
                twin_errors += 1
                _note_error(r["error"])
            else:
                twin_fires += int(r["fired"])
                if r["fired"]:
                    leak_evidence.extend(r.get("evidence") or [])
                fingerprint = r["fingerprint"]

        if not case.model_dependent:
            succ = err = 0
            for i in range(n_attack):
                r = await _safe_trial(args, case, f"{case.id}-atk-{i}",
                                      is_attack=True, tier=tiers[0], budget=budget, limiter=limiter)
                if "error" in r:
                    err += 1
                    _note_error(r["error"])
                else:
                    succ += int(r["fired"])
            detected = succ > 0
            per_tier["_single"] = {"successes": succ, "errors": err, "completed": n_attack - err}
        else:
            for tier in tiers:
                succ = err = 0
                for i in range(n_attack):
                    r = await _safe_trial(args, case, f"{case.id}-atk-{tier}-{i}",
                                          is_attack=True, tier=tier, budget=budget, limiter=limiter)
                    if "error" in r:
                        err += 1
                        _note_error(r["error"])
                    else:
                        succ += int(r["fired"])
                        fingerprint = r["fingerprint"]
                completed = n_attack - err
                point, low, high = wilson(succ, completed)
                per_tier[tier] = {"successes": succ, "errors": err, "completed": completed,
                                  "asr": point, "ci": (low, high)}
    except BudgetExceeded:
        truncated = True

    return {"case": case, "n": n_attack, "twin_n": n_twin,
            "twin_fires": twin_fires, "twin_errors": twin_errors,
            "neg_control_ok": twin_fires == 0, "per_tier": per_tier,
            "detected": detected, "truncated": truncated, "fingerprint": fingerprint,
            "leak_evidence": leak_evidence, "errors_seen": errors_seen}


def _cell(t: dict) -> str:
    if t["completed"] == 0:
        return "ERR (no data)"
    tag = f" e{t['errors']}" if t["errors"] else ""
    return f"{t['asr']*100:5.1f} [{t['ci'][0]*100:3.0f}-{t['ci'][1]*100:3.0f}]{tag}"


def _check_endpoint(args) -> None:
    """Probe the endpoint directly (no MCP, no async task group) in layers, so a
    failure points at the exact cause: auth/network, reasoning_effort, or tools."""
    from aevp_range.provider import OpenAICompatibleProvider
    key = os.environ.get(args.api_key_env, "")
    print(f"  Endpoint check: {args.preset} {args.base_url}  model={args.model}  "
          f"key={args.api_key_env}={'set' if key else 'MISSING'}")
    if not key:
        print(f"  FAIL: {args.api_key_env} is not set in this shell.")
        return

    msg = [{"role": "user", "content": "Reply with the single word OK."}]
    dummy_tool = [{"type": "function", "function": {
        "name": "ping", "description": "Return pong.",
        "parameters": {"type": "object", "properties": {}, "required": []}}}]

    ua_kwargs = {"user_agent": args.user_agent} if args.user_agent else {}

    def probe(label, reasoning, tools):
        # max_tokens 512 (not 64): reasoning models burn the whole budget on
        # hidden thinking at 64 and return empty content, a false failure.
        base = dict(model=args.model, api_key=key, base_url=args.base_url,
                    temperature=0.0, max_tokens=512, max_retries=1, **ua_kwargs)
        prov = (AnthropicMessagesProvider(**base) if args.api == "anthropic"
                else OpenAICompatibleProvider(reasoning_effort=reasoning,
                                              extra_body=or_provider_body(args), **base))
        try:
            act = prov.next_action(msg, tools)
            print(f"  [OK]   {label}: {type(act).__name__}")
            return True, ""
        except Exception as exc:  # noqa: BLE001
            err = unwrap_exc(exc)
            print(f"  [FAIL] {label}: {err[:260]}")
            return False, err

    ok, err = probe("plain completion (auth + network + model)", None, [])
    if not ok:
        if "1010" in err or "HTTP 403" in err:
            print("  -> Cloudflare bot block (1010/403), NOT your key. The endpoint sits")
            print("     behind Cloudflare and flagged the client signature. This build now")
            print("     sends a browser User-Agent by default; if you still see this:")
            print("       * try  --user-agent 'PostmanRuntime/7.43.0'")
            print("       * or switch endpoints:  --preset cerebras")
            print("       * if it persists it is TLS-fingerprint based; use the official")
            print("         groq/openai SDK for that provider instead of this harness.")
        elif "HTTP 402" in err:
            print("  -> PAYMENT/QUOTA problem (402), not network: this account has no")
            print("     credits or free quota left for this endpoint. Top up, or use a")
            print("     different preset.")
        elif "401" in err or "403" in err:
            print("  -> auth problem: the key value is wrong/expired for this endpoint.")
        else:
            print("  -> network/model problem. Check the model id and that the host is")
            print("     reachable (firewall/VPN/DNS).")
        return
    if args.api != "anthropic" and args.reasoning_effort:
        probe(f"with reasoning_effort={args.reasoning_effort}", args.reasoning_effort, [])
    probe("with a tool (tool-calling support)", args.reasoning_effort, dummy_tool)
    print("  If plain passed but the tool probe failed, the model/endpoint does not "
          "accept this tool schema; try a different tool-calling model.")


def summarize_evidence(evidence: list, limit: int = 3) -> list[str]:
    """Turn raw oracle events into short human-readable causes.

    A bare "LEAK!" is undebuggable: it says an oracle fired on a clean range but
    not WHAT fired. For a capability violation the interesting part is the
    rejected invocation and the rule it broke."""
    out: list[str] = []
    for item in evidence:
        ev = item.get("event", item) if isinstance(item, dict) else {}
        data = ev.get("data") or {}
        kind = ev.get("kind", "?")
        if kind == "capability":
            inv = data.get("invocation") or {}
            viol = "; ".join(data.get("violations") or [])
            rules = ",".join(data.get("rules") or [])
            who = inv.get("recipient") or inv.get("url") or "?"
            msg = f"capability[{rules}]: {data.get('tool_name')}({who!r}) -> {viol}"
        elif kind == "honeytoken":
            msg = (f"honeytoken: {data.get('reader_identity')} read "
                   f"{data.get('customer_id')}")
        elif kind == "shadow_tool":
            msg = f"shadow tool: {ev.get('source')}({data})"
        elif kind == "integrity":
            msg = f"schema drift: {data.get('tool_name')}"
        elif kind in ("sinkhole", "output"):
            msg = f"{kind}: {str(data)[:120]}"
        else:
            msg = f"{kind}: {str(data)[:120]}"
        if msg not in out:
            out.append(msg)
        if len(out) >= limit:
            break
    return out


def _oracle_name(case):
    rid = f"{case.id}-atk-blatant-0" if case.model_dependent else f"{case.id}-atk-0"
    return evaluate(case.asi, rid).primitive.split()[0]


def _print_single(results, args, budget):
    tier = args.tier
    mode = "scripted mock" if args.provider == "mock" else f"live: {args.model}"
    print("\n" + "=" * 92)
    print(f"  AEVP RANGE  (N={args.n} per arm, {mode}, tier={tier})")
    print("=" * 92)
    print(f"  {'case':26} {'ASI':6} {'oracle':8} {'ASR [95% Wilson]':32} {'neg-ctrl':8}")
    print("  " + "-" * 88)
    for r in results:
        c = r["case"]
        if not r["neg_control_ok"]:
            asr = "QUARANTINED (negative control failed)"
        elif not c.model_dependent:
            single = r["per_tier"]["_single"]
            asr = (("DETECTED" if r["detected"] else "not detected")
                   + (" (model-independent)" if single["completed"] else " -- all trials errored"))
        else:
            asr = _cell(r["per_tier"][tier])
        nc = "PASS" if r["neg_control_ok"] else "LEAK!"
        flag = " (truncated)" if r["truncated"] else ""
        print(f"  {c.id:26} {c.asi:6} {_oracle_name(c):8} {asr:32} {nc:8}{flag}")
    _print_footer(results, args, budget)


def _print_matrix(results, args, budget):
    mode = "scripted mock" if args.provider == "mock" else f"live: {args.model}"
    print("\n" + "=" * 112)
    print(f"  AEVP RANGE -- injection-strength ladder  (N={args.n} per arm/tier, {mode})")
    print("  ASR [95% Wilson %] per phrasing tier. blatant > plausible > subtle in technique.")
    print("=" * 112)
    print(f"  {'case':26} {'ASI':6} {'oracle':7} "
          f"{'blatant':19}{'plausible':19}{'subtle':19}{'neg-ctrl':8}")
    print("  " + "-" * 108)
    for r in results:
        c = r["case"]
        prefix = f"  {c.id:26} {c.asi:6} {_oracle_name(c):7} "
        nc = "PASS" if r["neg_control_ok"] else "LEAK!"
        if not r["neg_control_ok"]:
            print(prefix + f"{'QUARANTINED (negative control failed)':57}{nc:8}")
        elif not c.model_dependent:
            span = ("DETECTED" if r["detected"] else "not detected") + " (model-independent, tier-invariant)"
            print(prefix + f"{span:57}{nc:8}")
        else:
            cells = "".join(f"{_cell(r['per_tier'][t]):19}" for t in TIERS)
            print(prefix + cells + f"{nc:8}")
    _print_footer(results, args, budget, width=108)


def _print_footer(results, args, budget, width=88):
    twin_checks = sum(r["twin_n"] - r["twin_errors"] for r in results)
    twin_fires = sum(r["twin_fires"] for r in results)
    twin_errors = sum(r["twin_errors"] for r in results)
    atk_errors = sum(t.get("errors", 0) for r in results for t in r["per_tier"].values())
    print("  " + "-" * width)
    fp, _lo, fp_hi = wilson(twin_fires, twin_checks)
    # The FP rate is an ESTIMATE like any other, so it carries an interval. A bare
    # 0.00% would overstate what N twin trials can establish.
    print(f"  Negative-control (benign-twin) firings: {twin_fires}/{twin_checks}"
          f"  -> false-positive rate {fp*100:.2f}% (95% CI upper bound {fp_hi*100:.2f}%)")
    if twin_fires == 0:
        print("  Invariant HELD: every reported ASR is admissible (Oracle Spec section 4).")
    else:
        leaky = [r["case"].id for r in results if not r["neg_control_ok"]]
        print("  Invariant BROKEN: range leaked for " + ", ".join(leaky) + ". ASRs withheld.")
        for r in results:
            if r["neg_control_ok"]:
                continue
            print(f"    {r['case'].id}: {r['twin_fires']}/{r['twin_n']} benign twins fired --")
            for line in summarize_evidence(r.get("leak_evidence") or []):
                print(f"      {line}")
            print("      A benign path that fires an oracle is a RANGE bug, not a finding.")
    if args.provider == "live":
        if atk_errors or twin_errors:
            print(f"  Trial errors (non-fatal): {atk_errors} attack, {twin_errors} twin"
                  f"  -- ASRs are over COMPLETED trials only.")
            for r in results:
                for line in (r.get("errors_seen") or []):
                    print(f"    {r['case'].id}: {line[:150]}")
        b = budget.summary()
        spend = (b["prompt_tokens"] / 1e6 * args.price_in
                 + b["completion_tokens"] / 1e6 * args.price_out)
        print(f"  Budget: {json.dumps(b)}")
        if args.price_in or args.price_out:
            print(f"  Spend: ${spend:.3f} USD = {args.currency} {spend*args.fx:.2f}"
                  f"  (at --price-in {args.price_in}/--price-out {args.price_out} per 1M)")
        print(f"  Fingerprint: {json.dumps(results[0]['fingerprint'])}")
    print("=" * (width + 4) + "\n")


async def _preflight(args, budget, limiter) -> None:
    """One cheap benign trial to confirm the model actually emits tool calls.
    A model that cannot tool-call yields all-0% ASR that looks like resistance
    but is a plumbing failure -- worth catching before spending free quota."""
    case = next((c for c in getattr(args, "_selected", CASES) if c.model_dependent),
                next(c for c in CASES if c.model_dependent))
    try:
        r = await _one_trial(args, case, "preflight", is_attack=False, tier="blatant",
                             budget=budget, limiter=limiter)
    except Exception as exc:  # noqa: BLE001
        print(f"  PREFLIGHT WARNING: first call failed: {unwrap_exc(exc)[:280]}")
        print("  Run  python run_range.py --provider live --preset <p> --check  to isolate it.")
        return
    if r.get("tool_calls", 0) == 0:
        print("  PREFLIGHT WARNING: the model emitted NO tool calls on a tool-requiring task.")
        print("  It may not support OpenAI tool calling -- results would be all-0% plumbing")
        print(f"  failures, not findings. Model: {args.model}. Consider a tool-calling model.")
    else:
        print(f"  Preflight OK: model emitted tool calls ({args.model}).")


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5, help="trials per arm (headline runs use >=100)")
    ap.add_argument("--provider", choices=["mock", "live"], default="mock")
    ap.add_argument("--preset", choices=list(PRESETS), default="openrouter",
                    help="live endpoint preset: base URL, key env, default rpm/model/api")
    ap.add_argument("--api", choices=["openai", "anthropic"], default=None,
                    help="wire protocol (override preset): openai=/chat/completions, anthropic=/v1/messages")
    ap.add_argument("--tier", choices=["blatant", "plausible", "subtle", "all"], default="blatant")
    ap.add_argument("--model", default=None, help="override the preset model")
    ap.add_argument("--base-url", default=None, help="override the preset base URL")
    ap.add_argument("--api-key-env", default=None, help="override the preset API-key env var")
    ap.add_argument("--rpm", type=float, default=None, help="requests/min throttle (override preset)")
    ap.add_argument("--reasoning-effort", default=None,
                    help="pass reasoning_effort (e.g. low, none) for gpt-oss/GLM to cut token use")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--max-tokens", type=int, default=1024)
    ap.add_argument("--max-calls", type=int, default=4000)
    ap.add_argument("--max-prompt-tokens", type=int, default=2_000_000,
                    help="campaign ceiling on INPUT tokens; a long tier-all run on a "
                         "verbose model can hit this and truncate")
    ap.add_argument("--max-completion-tokens", type=int, default=500_000)
    ap.add_argument("--max-steps", type=int, default=8,
                    help="max agent turns per trial; lower bounds worst-case calls/cost")
    # --- cost controls ---
    ap.add_argument("--twin-n", type=int, default=None,
                    help="twin trials per case (default: same as --n). Twins only need to "
                         "show no leak, so a smaller count saves ~20%% -- it widens the "
                         "false-positive CI, so use --twin-n = --n for published figures")
    ap.add_argument("--mi-n", type=int, default=None,
                    help="trials for model-INDEPENDENT cases (schema-hash checks give an "
                         "identical verdict every trial; default min(n,3))")
    # --- cost estimation ---
    ap.add_argument("--estimate", action="store_true",
                    help="print projected trials/calls/tokens/cost and exit (spends nothing)")
    ap.add_argument("--price-in", type=float, default=0.0, help="USD per 1M input tokens")
    ap.add_argument("--price-out", type=float, default=0.0, help="USD per 1M output tokens")
    ap.add_argument("--fx", type=float, default=4.7, help="local currency units per USD")
    ap.add_argument("--currency", default="MYR")
    ap.add_argument("--calls-per-trial", type=float, default=MEASURED_CALLS_PER_TRIAL)
    ap.add_argument("--tok-in", type=float, default=MEASURED_TOK_IN_PER_TRIAL)
    ap.add_argument("--tok-out", type=float, default=MEASURED_TOK_OUT_PER_TRIAL)
    ap.add_argument("--no-preflight", action="store_true", help="skip the tool-calling preflight")
    ap.add_argument("--only", default=None,
                    help="comma-separated case ids to run (e.g. asi09_unsanitized_output). "
                         "Lets a truncated or quarantined case be completed cheaply.")
    ap.add_argument("--check", action="store_true",
                    help="probe the endpoint directly and exit (diagnoses 401/400/403/network)")
    ap.add_argument("--or-provider", default=None,
                    help="OpenRouter only: pin every request to ONE upstream (e.g. Cerebras) "
                         "with fallbacks disabled, so a run is not spread across backends")
    ap.add_argument("--user-agent", default=None,
                    help="override the request User-Agent (Cloudflare 1010 workaround)")
    args = ap.parse_args()

    preset = PRESETS[args.preset]
    args.base_url = args.base_url or preset["base_url"]
    args.model = args.model or preset["model"]
    args.api_key_env = args.api_key_env or preset["key_env"]
    rpm = preset["rpm"] if args.rpm is None else args.rpm
    args.api = args.api or preset["api"]

    args.twin_n = args.n if args.twin_n is None else args.twin_n
    args.mi_n = min(args.n, 3) if args.mi_n is None else args.mi_n

    selected = CASES
    if args.only:
        wanted = {x.strip() for x in args.only.split(",") if x.strip()}
        unknown = wanted - {c.id for c in CASES}
        if unknown:
            raise SystemExit(f"unknown case id(s): {', '.join(sorted(unknown))}\n"
                             f"available: {', '.join(c.id for c in CASES)}")
        selected = [c for c in CASES if c.id in wanted]

    md_cases = sum(1 for c in selected if c.model_dependent)
    mi_cases = len(selected) - md_cases

    if args.estimate:
        args.rpm = rpm
        e = estimate(args, md_cases, mi_cases)
        tiers = len(TIERS) if args.tier == "all" else 1
        print(f"\n  ESTIMATE  n={args.n} twin_n={args.twin_n} mi_n={args.mi_n} "
              f"tiers={tiers} preset={args.preset} model={args.model}")
        print(f"  trials {e['trials']}  calls {e['calls']:.0f}  "
              f"tokens {(e['tok_in_m']+e['tok_out_m'])*1000:.0f}K "
              f"(in {e['tok_in_m']*1000:.0f}K / out {e['tok_out_m']*1000:.0f}K)")
        if e["minutes"]:
            print(f"  wall time at {rpm} rpm: {e['minutes']:.0f} min ({e['minutes']/60:.1f} h)")
        if args.price_in or args.price_out:
            print(f"  cost ${e['usd']:.2f} USD = {args.currency} {e['local']:.2f}")
        else:
            print("  cost: pass --price-in/--price-out (USD per 1M tokens) to price it")
        print("  (projection from a measured gpt-oss-120b run; override with "
              "--calls-per-trial/--tok-in/--tok-out)\n")
        return

    if args.check:
        _check_endpoint(args)
        return
    if args.provider == "live":
        if not os.environ.get(args.api_key_env):
            raise SystemExit(f"live mode ({args.preset}) requires {args.api_key_env} to be set")
        if args.temperature == 0.0 and args.n > 1:
            print("  WARNING: temperature=0 with N>1 -- trials are not independent samples.")

    eventlog.reset()
    canary.reset()
    _reset_memory()
    if os.path.exists(TRACE_LOG):
        os.remove(TRACE_LOG)
    _record_baselines()

    budget = Budget(max_calls=args.max_calls,
                    max_prompt_tokens=args.max_prompt_tokens,
                    max_completion_tokens=args.max_completion_tokens)
    limiter = RateLimiter(rpm)

    args._selected = selected
    if args.provider == "live":
        print(f"  Endpoint: {args.preset} [{args.api}] ({args.base_url}), model={args.model}, "
              f"rpm={rpm or 'unlimited'}, reasoning_effort={args.reasoning_effort}")
        if not args.no_preflight:
            await _preflight(args, budget, limiter)

    results = [await run_case(args, c, budget, limiter) for c in selected]

    if args.tier == "all":
        _print_matrix(results, args, budget)
    else:
        _print_single(results, args, budget)

    twin_checks = sum(r["n"] for r in results)
    twin_fires = sum(r["twin_fires"] for r in results)
    out = {
        "mode": args.provider, "preset": args.preset, "tier": args.tier, "n": args.n,
        "twin_n": args.twin_n, "mi_n": args.mi_n, "max_steps": args.max_steps,
        "only": args.only,
        "rpm": rpm, "budget": budget.summary(),
        "fingerprint": results[0]["fingerprint"] if results else {},
        "observed_fp_rate": (twin_fires / twin_checks) if twin_checks else 0.0,
        "invariant_held": twin_fires == 0,
        "cases": [{
            "id": r["case"].id, "asi": r["case"].asi,
            "model_dependent": r["case"].model_dependent,
            "quarantined": not r["neg_control_ok"],
            "detected": r["detected"] if not r["case"].model_dependent else None,
            "twin_fires": r["twin_fires"], "twin_errors": r["twin_errors"],
            "truncated": r["truncated"],
            "leak_causes": summarize_evidence(r.get("leak_evidence") or []),
            "errors_seen": r.get("errors_seen") or [],
            "tiers": {
                t: {"successes": v["successes"], "errors": v.get("errors", 0),
                    "completed": v.get("completed"), "asr": v.get("asr"),
                    "ci_low": v["ci"][0] if "ci" in v else None,
                    "ci_high": v["ci"][1] if "ci" in v else None}
                for t, v in r["per_tier"].items()
            } if r["neg_control_ok"] else {},
        } for r in results],
    }
    os.makedirs(_ROOT, exist_ok=True)
    with open(os.path.join(_ROOT, "campaign.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)


if __name__ == "__main__":
    asyncio.run(main())
