"""Compare campaign results across models.

    python compare_campaigns.py results/cerebras-N30-*.json results/sonnet-N30-*.json

Prints one row per (case, tier) with each model's ASR and 95% Wilson interval
side by side. Quarantined cells are shown as such and never as a number:
a result whose negative control failed is inadmissible, not merely uncertain.
"""
import argparse
import json
import os

TIERS = ("blatant", "plausible", "subtle")


def load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    fp = data.get("fingerprint") or {}
    data["_label"] = fp.get("model") or os.path.basename(path)
    return data


def cell(case: dict, tier: str) -> str:
    if case.get("quarantined"):
        return "QUARANTINED"
    if not case.get("model_dependent"):
        return "DETECTED" if case.get("detected") else "not detected"
    t = (case.get("tiers") or {}).get(tier)
    if not t:
        return "-"
    if not t.get("completed"):
        return "ERR"
    err = f" e{t['errors']}" if t.get("errors") else ""
    return f"{t['asr']*100:5.1f} [{t['ci_low']*100:3.0f}-{t['ci_high']*100:3.0f}]{err}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()

    runs = [load(f) for f in args.files]
    labels = [r["_label"] for r in runs]
    width = max(22, max(len(x) for x in labels) + 2)

    print()
    print("=" * (34 + width * len(runs)))
    print("  AEVP cross-model comparison -- ASR [95% Wilson %] per phrasing tier")
    print("=" * (34 + width * len(runs)))
    for r in runs:
        fp = r.get("fingerprint") or {}
        held = "HELD" if r.get("invariant_held") else "BROKEN"
        print(f"  {r['_label']:22} N={r.get('n')} twin_n={r.get('twin_n')} "
              f"temp={fp.get('temperature')} invariant={held}")
    print("-" * (34 + width * len(runs)))
    print(f"  {'case':24} {'tier':11}" + "".join(f"{x:{width}}" for x in labels))
    print("-" * (34 + width * len(runs)))

    ids = [c["id"] for c in runs[0].get("cases", [])]
    for cid in ids:
        cases = [next((c for c in r.get("cases", []) if c["id"] == cid), {}) for r in runs]
        model_dep = cases[0].get("model_dependent", True)
        tiers = TIERS if model_dep else ("_single",)
        for tier in tiers:
            label = tier if model_dep else "(tier-inv)"
            print(f"  {cid:24} {label:11}" + "".join(f"{cell(c, tier):{width}}" for c in cases))
        print()

    print("-" * (34 + width * len(runs)))
    for r in runs:
        b = r.get("budget") or {}
        print(f"  {r['_label']:22} calls {b.get('calls')}  "
              f"fp_rate {r.get('observed_fp_rate', 0)*100:.2f}%")
    print("=" * (34 + width * len(runs)))
    print()


if __name__ == "__main__":
    main()
