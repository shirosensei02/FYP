"""Aggregate evaluation metrics over the stored pipeline runs.

Reads ``fyp_patches.all_attempts`` and ``fyp_patches.attempt_costs`` (read-only)
and reports the metrics used by PatchEval (Wei et al., 2025, arXiv:2511.11019)
that the oracle-based pipeline can now compute: PoC-verified repair rate, the
plausible-vs-verified split, LLM-judge agreement with the dynamic oracle, repair
rate by vendor-patch size and vulnerability class, cost per verified pass, plus
two coverage metrics specific to this pipeline (oracle acceptance, context hit).

One run is the final stored attempt per ``attempt_id``. Documents written
before the oracle existed lack oracle fields; they count as runs but are
excluded from the oracle-based rates, and the report states how many remain.

    python metrics_report.py [--package NAME] [--model ID] [--since YYYY-MM-DD]
                             [--oracle-only] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from cost_log import diff_line_counts

_TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec)(/|$)|\.(test|spec)\.[cm]?[jt]sx?$")
_SIZE_BUCKETS = (("1-5 lines", 1, 5), ("6-20 lines", 6, 20), (">20 lines", 21, None))
_CLASS_PATTERNS = (
    ("prototype pollution", r"prototype pollution|__proto__"),
    ("command injection", r"command injection|arbitrary command|os command|child_process|shell"),
    ("path traversal", r"path traversal|directory traversal|zip slip|arbitrary file|outside (?:the )?(?:output )?director"),
    ("ReDoS", r"redos|regular expression denial|catastrophic|backtracking|regex"),
    ("SSRF", r"ssrf|server-side request forgery"),
    ("XSS", r"cross-site scripting|\bxss\b"),
    ("SQL injection", r"sql injection"),
    ("cryptography", r"cryptograph|hmac|signature|certificate|\btls\b|weak random|insecure random"),
    ("denial of service", r"denial of service|\bdos\b|infinite loop|crash"),
)


def _rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def classify_vulnerability(doc: dict[str, Any]) -> str:
    """Keyword-derived class; the stored findings carry no CWE ids."""
    answer = doc.get("answer_key") or {}
    findings = doc.get("vulnerabilities") or []
    text = " ".join(
        [_text(answer.get("summary"))]
        + [_text(item.get("description")) for item in findings[:1] if isinstance(item, dict)]
    ).lower()
    for label, pattern in _CLASS_PATTERNS:
        if re.search(pattern, text):
            return label
    return "other"


def _sort_key(doc: dict[str, Any]) -> tuple:
    stamp = doc.get("timestamp")
    stamp = stamp.timestamp() if isinstance(stamp, datetime) else 0.0
    return (doc.get("attempt_number") or 0, stamp)


def final_attempts(docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The last stored attempt of each run; a document without a run id is its own run."""
    runs: dict[Any, dict[str, Any]] = {}
    for index, doc in enumerate(docs):
        run_id = doc.get("attempt_id") or ("anonymous", index)
        if run_id not in runs or _sort_key(doc) >= _sort_key(runs[run_id]):
            runs[run_id] = doc
    return list(runs.values())


def _oracle_status(doc: dict[str, Any]) -> str | None:
    return (doc.get("generated_patch_oracle_validation") or {}).get("status")


def _has_oracle_data(doc: dict[str, Any]) -> bool:
    return bool(_oracle_status(doc) or (doc.get("oracle_validation") or {}).get("status"))


def classify_outcome(doc: dict[str, Any]) -> str:
    """Mirror patch_validation: pass needs the oracle; compatibility alone is inconclusive."""
    if doc.get("passed"):
        return "pass"
    compatible = doc.get("regression_status") == "NO_REGRESSION" and doc.get("generation_status") != "failed"
    if compatible and _oracle_status(doc) not in {"SECURITY_FAIL", "REGRESSION"}:
        return "inconclusive"
    return "fail"


def _vendor_files(doc: dict[str, Any]) -> list[str]:
    files = (doc.get("answer_key") or {}).get("files") or []
    normalised = [path.replace("\\", "/").removeprefix("./") for path in files if isinstance(path, str)]
    return [path for path in normalised if not _TEST_PATH.search(path)]


def _vendor_lines(doc: dict[str, Any]) -> int | None:
    diff = (doc.get("answer_key") or {}).get("diff")
    if not isinstance(diff, str) or not diff.strip():
        return None
    counts = diff_line_counts(diff)
    return counts["lines_added"] + counts["lines_removed"]


def _size_bucket(lines: int | None) -> str:
    if lines is None or lines < 1:
        return "unknown"
    for label, low, high in _SIZE_BUCKETS:
        if lines >= low and (high is None or lines <= high):
            return label
    return "unknown"


def _file_hit(vendor: str, shown: list[str]) -> bool:
    return any(item == vendor or item.endswith("/" + vendor) or vendor.endswith("/" + item) for item in shown)


def _breakdown(runs: list[dict[str, Any]], key) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for doc in runs:
        groups[key(doc)].append(doc)
    return {
        label: {
            "runs": len(items),
            "passes": sum(1 for doc in items if doc.get("passed")),
            "repair_rate": _rate(sum(1 for doc in items if doc.get("passed")), len(items)),
        }
        for label, items in sorted(groups.items())
    }


def summarize(runs: list[dict[str, Any]]) -> dict[str, Any]:
    outcomes = {"pass": 0, "inconclusive": 0, "fail": 0}
    for doc in runs:
        outcomes[classify_outcome(doc)] += 1

    oracle_runs = [doc for doc in runs if _has_oracle_data(doc)]
    accepted = sum(1 for doc in oracle_runs if (doc.get("accepted_oracle") or {}).get("status") == "accepted")
    oracle_status: dict[str, int] = defaultdict(int)
    for doc in oracle_runs:
        oracle_status[(doc.get("oracle_validation") or {}).get("status") or "none"] += 1
    security: dict[str, int] = defaultdict(int)
    for doc in oracle_runs:
        security[_oracle_status(doc) or "none"] += 1

    pairs = agree = uncertain = 0
    for doc in runs:
        verdict = (doc.get("adversarial_evaluation") or {}).get("genuine_fix")
        status = _oracle_status(doc)
        if status not in {"SECURITY_PASS", "SECURITY_FAIL"} or verdict is None:
            continue
        if verdict == "uncertain":
            uncertain += 1
            continue
        pairs += 1
        agree += int((verdict == "true") == (status == "SECURITY_PASS"))

    with_vendor = [doc for doc in runs if _vendor_files(doc)]
    any_hit = 0
    recalls: list[float] = []
    for doc in with_vendor:
        shown = [p.replace("\\", "/") for p in doc.get("context_file_paths") or [] if isinstance(p, str)]
        hits = [_file_hit(vendor, shown) for vendor in _vendor_files(doc)]
        any_hit += int(any(hits))
        recalls.append(sum(hits) / len(hits))

    selections = [
        doc["candidate_selection"] for doc in runs
        if (doc.get("candidate_selection") or {}).get("status") == "selected"
    ]
    costed = [doc["_run_cost"] for doc in runs if doc.get("_run_cost") is not None]
    costed_passes = sum(
        1 for doc in runs if doc.get("_run_cost") is not None and classify_outcome(doc) == "pass"
    )
    oracle_passes = sum(1 for doc in oracle_runs if classify_outcome(doc) == "pass")
    return {
        "runs": len(runs),
        "outcomes": outcomes,
        "pass_rate_all_runs": _rate(outcomes["pass"], len(runs)),
        "legacy_runs": len(runs) - len(oracle_runs),
        "poc_verified_rate": _rate(oracle_passes, len(oracle_runs)),
        "compatible_not_verified": outcomes["inconclusive"],
        "oracle": {
            "runs_with_oracle_data": len(oracle_runs),
            "acceptance_rate": _rate(accepted, len(oracle_runs)),
            "baseline_status": dict(oracle_status),
            "generated_patch_status": dict(security),
        },
        "judge_vs_oracle": {
            "decided_pairs": pairs,
            "agreement": _rate(agree, pairs),
            "uncertain_verdicts": uncertain,
        },
        "by_vendor_patch_size": _breakdown(runs, lambda doc: _size_bucket(_vendor_lines(doc))),
        "by_vulnerability_class": _breakdown(runs, classify_vulnerability),
        "candidate_selection": {
            "runs_with_selection": len(selections),
            "mean_distinct_candidates": (
                sum(item.get("unique") or 0 for item in selections) / len(selections) if selections else None
            ),
            "primary_passed_oracle": sum(1 for item in selections if item.get("primary_status") == "SECURITY_PASS"),
            "any_candidate_passed_oracle": sum(1 for item in selections if (item.get("oracle_passes") or 0) > 0),
            "chosen_not_primary": sum(1 for item in selections if item.get("chosen_is_primary") is False),
        },
        "context_hit": {
            "runs_with_vendor_source_files": len(with_vendor),
            "any_vendor_file_shown": _rate(any_hit, len(with_vendor)),
            "mean_vendor_file_recall": (sum(recalls) / len(recalls)) if recalls else None,
        },
        "cost": {
            "runs_with_cost_data": len(costed),
            "total_usd": sum(costed),
            "per_run_usd": _rate(sum(costed), len(costed)),
            "per_verified_pass_usd": _rate(sum(costed), costed_passes),
        },
    }


def compute_metrics(
    attempt_docs: list[dict[str, Any]],
    cost_docs: list[dict[str, Any]] | None = None,
    *,
    oracle_only: bool = False,
) -> dict[str, Any]:
    cost_by_run: dict[Any, float] = {}
    for item in cost_docs or []:
        run_id = item.get("run_attempt_id")
        if run_id is not None:
            cost_by_run[run_id] = cost_by_run.get(run_id, 0.0) + float((item.get("totals") or {}).get("cost") or 0)
    runs = [{**doc, "_run_cost": cost_by_run.get(doc.get("attempt_id"))} for doc in final_attempts(attempt_docs)]
    if oracle_only:
        runs = [doc for doc in runs if _has_oracle_data(doc)]
    by_model: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for doc in runs:
        by_model[doc.get("model_used") or "unknown"].append(doc)
    return {
        "attempts_stored": len(attempt_docs),
        "overall": summarize(runs),
        "by_model": {model: summarize(items) for model, items in sorted(by_model.items())},
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _usd(value: float | None) -> str:
    return "n/a" if value is None else f"${value:.4f}"


def _table(title: str, rows: dict[str, dict[str, Any]]) -> list[str]:
    lines = [title]
    for label, row in rows.items():
        lines.append(f"  {label:<22} {row['passes']:>3}/{row['runs']:<3} passed    ({_pct(row['repair_rate'])})")
    return lines


def render(report: dict[str, Any]) -> str:
    overall = report["overall"]
    out = [
        f"attempts stored: {report['attempts_stored']}    runs (final attempt per run): {overall['runs']}",
        "",
        "Outcomes (derived the way patch_validation classifies):",
        "  " + "   ".join(f"{name}: {count}" for name, count in overall["outcomes"].items()),
        f"  pass rate, all runs      : {_pct(overall['pass_rate_all_runs'])}"
        f"   ({overall['legacy_runs']} legacy runs had no oracle: their 'pass' means build+tests only)",
        f"  PoC-verified repair rate : {_pct(overall['poc_verified_rate'])}"
        f"   (oracle-era runs only: the exploit must be blocked)",
        f"  compatible but unverified: {overall['compatible_not_verified']} (package imports; no oracle verdict)",
        "",
    ]
    oracle = overall["oracle"]
    out += [
        f"Oracle coverage ({oracle['runs_with_oracle_data']} runs carry oracle data; older runs are excluded):",
        f"  acceptance rate          : {_pct(oracle['acceptance_rate'])}",
        f"  baseline status          : {oracle['baseline_status']}",
        f"  generated-patch status   : {oracle['generated_patch_status']}",
        "",
    ]
    judge = overall["judge_vs_oracle"]
    out += [
        "LLM judge vs. dynamic oracle (PatchEval reports 76-81% for its judges):",
        f"  agreement                : {_pct(judge['agreement'])} over {judge['decided_pairs']} decided runs"
        f" ({judge['uncertain_verdicts']} 'uncertain' verdicts excluded)",
        "",
    ]
    out += _table("Repair rate by vendor-patch size:", overall["by_vendor_patch_size"]) + [""]
    out += _table("Repair rate by vulnerability class (keyword-derived):", overall["by_vulnerability_class"]) + [""]
    sampling = overall["candidate_selection"]
    if sampling["runs_with_selection"]:
        out += [
            f"Candidate sampling ({sampling['runs_with_selection']} runs compared several distinct patches):",
            f"  primary (temperature 0) blocked the exploit : {sampling['primary_passed_oracle']}",
            f"  any sampled candidate blocked it            : {sampling['any_candidate_passed_oracle']}"
            f"   <- the gap is what sampling bought",
            f"  selection replaced the primary              : {sampling['chosen_not_primary']}",
            f"  mean distinct candidates                    : {sampling['mean_distinct_candidates']:.1f}",
            "",
        ]
    context = overall["context_hit"]
    out += [
        f"Context hit ({context['runs_with_vendor_source_files']} runs with a vendor source file):",
        f"  any vendor file shown    : {_pct(context['any_vendor_file_shown'])}",
        f"  mean vendor-file recall  : {_pct(context['mean_vendor_file_recall'])}",
        "",
    ]
    cost = overall["cost"]
    out += [
        f"Cost ({cost['runs_with_cost_data']} runs have cost data):",
        f"  total {_usd(cost['total_usd'])}   per run {_usd(cost['per_run_usd'])}   per verified pass {_usd(cost['per_verified_pass_usd'])}",
    ]
    if len(report["by_model"]) > 1:
        out += ["", "By model:"]
        for model, item in report["by_model"].items():
            out.append(
                f"  {model:<38} runs {item['runs']:>3}   passed {item['outcomes']['pass']:>3} "
                f"({_pct(item['pass_rate_all_runs'])})   PoC-verified {_pct(item['poc_verified_rate'])}"
                f"   per pass {_usd(item['cost']['per_verified_pass_usd'])}"
            )
    return "\n".join(out)


_EXCLUDED_FIELDS = {
    "raw_output": 0, "oracle_attempts": 0, "validation": 0,
    "baseline_validation": 0, "patched_validation": 0, "maintainer_eval": 0,
}


def load_documents(
    package: str | None = None, model: str | None = None, since: datetime | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from db import _COL_ATTEMPTS, _COL_COSTS, _get_db

    query: dict[str, Any] = {}
    if package:
        query["package_name"] = package
    if model:
        query["model_used"] = model
    if since:
        query["timestamp"] = {"$gte": since}
    database = _get_db()
    attempts = list(database[_COL_ATTEMPTS].find(query, _EXCLUDED_FIELDS))
    cost_query = {"package_name": package} if package else {}
    costs = list(database[_COL_COSTS].find(cost_query, {"_id": 0, "requests": 0}))
    return attempts, costs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate pipeline evaluation metrics from MongoDB.")
    parser.add_argument("--package", help="only this package name")
    parser.add_argument("--model", help="only this generator model id")
    parser.add_argument("--since", help="only attempts on or after YYYY-MM-DD (UTC)")
    parser.add_argument("--oracle-only", action="store_true", help="only runs that carry security-oracle data")
    parser.add_argument("--json", action="store_true", help="print the metrics as JSON")
    args = parser.parse_args(argv)
    since = None
    if args.since:
        try:
            since = datetime.strptime(args.since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            parser.error("--since must look like 2026-11-01")
    attempts, costs = load_documents(args.package, args.model, since)
    if not attempts:
        print("No stored attempts match.", file=sys.stderr)
        return 1
    report = compute_metrics(attempts, costs, oracle_only=args.oracle_only)
    if not report["overall"]["runs"]:
        print("No runs carry oracle data.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, default=str) if args.json else render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
