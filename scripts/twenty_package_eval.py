"""Build the 20-package x 2-model x 3-prompt batch config and summarise results.

  python scripts/twenty_package_eval.py config      # writes the batch config
  python batch_runner.py --config config/twenty_package.json \
      --results abalation/twenty_package_evaluation/results.jsonl
  python scripts/twenty_package_eval.py summary     # percentage tables
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "twenty_package.json"
RESULTS = ROOT / "abalation" / "twenty_package_evaluation" / "results.jsonl"
SUMMARY = ROOT / "abalation" / "twenty_package_evaluation" / "summary.md"

# Unversioned names use the version from the ablation (patch_runs.csv).
PACKAGES = [
    "shell-quote@1.8.3", "minimatch@3.0.4", "lodash@4.17.11", "drizzle-orm@0.45.1",
    "jsonwebtoken@8.5.1", "form-data@4.0.3", "next@15.2.2", "vite@8.0.4",
    "axios@1.7.3", "dompurify@3.2.3", "json5@2.2.1", "pidusage@1.1.4",
    "network@0.6.1", "jszip@3.7.1", "zip-local@0.3.4", "express-jwt@5.3.3",
    "web3-utils@4.2.0", "fs-git@1.0.1", "koa@2.15.3", "parse-server@8.6.74",
]
MODELS = ["openai/gpt-5.3-codex", "anthropic/claude-sonnet-5"]
PROMPTS = ["_generic", "_enriched", "_CoT"]
CATEGORIES = [
    ("supported_fix", "Supported fix"),
    ("needs_verification", "Needs verification"),
    ("security_failure", "Security failure"),
    ("functional_failure", "Functional failure"),
    ("inconclusive", "Inconclusive"),
]


def write_config(cost_cap: float = 500.0) -> None:
    entries = [
        {"package": spec, "num_runs": 1, "model": model, "prompt_suffix": prompt}
        for prompt in PROMPTS for spec in PACKAGES for model in MODELS
    ]
    CONFIG.write_text(json.dumps({
        "cost_cap": cost_cap, "max_retries": 1, "model_provider": "openrouter",
        "patch_scope": "single", "packages": entries,
    }, indent=2) + "\n")
    print(f"wrote {CONFIG} ({len(entries)} runs)")


def _table(rows: list[dict], title: str) -> str:
    total = len(rows)
    counts = Counter(r.get("final_category") for r in rows)
    lines = [f"### {title} (n={total})", "", "| Classification | Count | % |", "|---|---|---|"]
    for key, label in CATEGORIES:
        pct = 100 * counts[key] / total if total else 0
        lines.append(f"| {label} | {counts[key]} | {pct:.1f}% |")
    return "\n".join(lines)


def summarize() -> None:
    rows = [json.loads(l) for l in RESULTS.read_text().splitlines() if l.strip()]
    out = ["# Final classification by prompt version", ""]
    for prompt in PROMPTS:
        out += [_table([r for r in rows if r.get("prompt_suffix") == prompt], prompt.lstrip("_")), ""]
    out += ["## Per model", ""]
    for prompt in PROMPTS:
        for model in MODELS:
            sel = [r for r in rows if r.get("prompt_suffix") == prompt and r.get("model_name") == model]
            out += [_table(sel, f"{prompt.lstrip('_')} / {model}"), ""]
    errors = sum(1 for r in rows if r.get("error"))
    out.append(f"Runs with a pipeline exception (counted as Inconclusive): {errors} of {len(rows)}")
    text = "\n".join(out) + "\n"
    SUMMARY.write_text(text)
    print(text)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "config":
        write_config(float(sys.argv[2]) if len(sys.argv) > 2 else 500.0)
    elif cmd == "summary":
        summarize()
    else:
        raise SystemExit(__doc__)
