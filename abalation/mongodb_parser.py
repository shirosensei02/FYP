"""Export ablation runs from fyp_patches.ablation_costs to CSV.

Reads only. Opens its own client and does not create indexes, so a batch
run can keep writing other documents at the same time.

  python abalation/mongodb_parser.py
"""

from __future__ import annotations

import csv
import sys
import time
from pathlib import Path

from pymongo import MongoClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from db import (  # noqa: E402
    _COL_ABLATION,
    _CONNECT_RETRIES,
    _CONNECT_RETRY_BACKOFF_SECONDS,
    _DB_NAME,
    _MONGO_URI,
    _mongo_tls_options,
)

HERE = Path(__file__).resolve().parent
EXPORTS = (
    ("locator", HERE / "locator_runs.csv", HERE / "locator_loops.csv"),
    ("oracle", HERE / "oracle_runs.csv", HERE / "oracle_loops.csv"),
    ("patch", HERE / "patch_runs.csv", HERE / "patch_loops.csv"),
)

RUN_FIELDS = (
    "ablation_id",
    "node",
    "prompt_suffix",
    "package_name",
    "package_version",
    "vulnerability_id",
    "model",
    "max_loop",
    "total_loops",
    "token_in",
    "token_out",
    "total_tokens",
    "cost",
    "lines_added",
    "lines_removed",
    "outcome",
    "located",
    "expected",
    "category",
)
LOOP_FIELDS = (
    "ablation_id",
    "package_name",
    "prompt_suffix",
    "model",
    "loop",
    "call",
    "token_in",
    "token_out",
    "total_tokens",
    "cost",
    "lines_added",
    "lines_removed",
)


def categorise_locator(outcome: object) -> tuple[int | None, int | None, str | None]:
    """Label a locator ratio. Pass is every file, partial is some, fail is none."""
    if not isinstance(outcome, str) or outcome.count("/") != 1:
        return None, None, None
    left, right = outcome.split("/", 1)
    if not left.isdigit() or not right.isdigit():
        return None, None, None
    located = int(left)
    expected = int(right)
    if expected < 1:
        return located, expected, None
    if located == expected:
        return located, expected, "pass"
    if located == 0:
        return located, expected, "fail"
    if located < expected:
        return located, expected, "partial"
    return located, expected, None


def categorise_oracle(outcome: object) -> tuple[int | None, int | None, str | None]:
    """Label an oracle run. Pass is within 5 loops, partial is within 10, fail is none."""
    if outcome == "max_5":
        return None, None, "pass"
    if outcome == "max_10":
        return None, None, "partial"
    if outcome == "failed":
        return None, None, "fail"
    return None, None, None


def categorise(node: str, outcome: object) -> tuple[int | None, int | None, str | None]:
    if node in {"oracle", "patch"}:
        return categorise_oracle(outcome)
    return categorise_locator(outcome)


def run_row(document: dict) -> dict:
    totals = document.get("totals") or {}
    located, expected, category = categorise(str(document.get("node") or ""), totals.get("outcome"))
    return {
        "ablation_id": document.get("ablation_id"),
        "node": document.get("node"),
        "prompt_suffix": document.get("prompt_suffix"),
        "package_name": document.get("package_name"),
        "package_version": document.get("package_version"),
        "vulnerability_id": document.get("vulnerability_id"),
        "model": document.get("model"),
        "max_loop": document.get("max_loop"),
        "total_loops": totals.get("total_loops"),
        "token_in": totals.get("token_in"),
        "token_out": totals.get("token_out"),
        "total_tokens": totals.get("total_tokens"),
        "cost": totals.get("cost"),
        "lines_added": totals.get("lines_added"),
        "lines_removed": totals.get("lines_removed"),
        "outcome": totals.get("outcome"),
        "located": located,
        "expected": expected,
        "category": category,
    }


def loop_rows(document: dict) -> list[dict]:
    rows = []
    for item in document.get("loops") or []:
        if not isinstance(item, dict):
            continue
        rows.append({
            "ablation_id": document.get("ablation_id"),
            "package_name": document.get("package_name"),
            "prompt_suffix": document.get("prompt_suffix"),
            "model": document.get("model"),
            "loop": item.get("loop"),
            "call": item.get("call"),
            "token_in": item.get("token_in"),
            "token_out": item.get("token_out"),
            "total_tokens": item.get("total_tokens"),
            "cost": item.get("cost"),
            "lines_added": item.get("lines_added"),
            "lines_removed": item.get("lines_removed"),
        })
    return rows


def write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def connect() -> MongoClient:
    """Open a read client. Does not create indexes."""
    last_exc: Exception | None = None
    for attempt in range(1, _CONNECT_RETRIES + 1):
        try:
            client = MongoClient(
                _MONGO_URI,
                serverSelectionTimeoutMS=5_000,
                **_mongo_tls_options(_MONGO_URI),
            )
            client.admin.command("ping")
            return client
        except Exception as exc:
            last_exc = exc
            if attempt < _CONNECT_RETRIES:
                time.sleep(_CONNECT_RETRY_BACKOFF_SECONDS)
    assert last_exc is not None
    raise last_exc


def load_node(node: str) -> list[dict]:
    client = connect()
    try:
        cursor = client[_DB_NAME][_COL_ABLATION].find(
            {"node": node},
            {"_id": 0, "loops.response": 0},
        )
        return list(cursor)
    finally:
        client.close()


def export_node(node: str, runs_path: Path, loops_path: Path) -> None:
    documents = load_node(node)
    documents.sort(key=lambda doc: (
        str(doc.get("package_name") or ""),
        str(doc.get("prompt_suffix") or ""),
        str(doc.get("model") or ""),
        str(doc.get("ablation_id") or ""),
    ))
    runs = [run_row(document) for document in documents]
    loops = [row for document in documents for row in loop_rows(document)]
    write_csv(runs_path, RUN_FIELDS, runs)
    write_csv(loops_path, LOOP_FIELDS, loops)
    counts: dict[str | None, int] = {}
    for row in runs:
        counts[row["category"]] = counts.get(row["category"], 0) + 1
    print(f"{node} runs: {len(runs)} -> {runs_path}")
    print(f"{node} loops: {len(loops)} -> {loops_path}")
    print(
        "category: "
        + ", ".join(f"{name}={counts[name]}" for name in ("pass", "partial", "fail") if name in counts)
    )


def main() -> None:
    for node, runs_path, loops_path in EXPORTS:
        export_node(node, runs_path, loops_path)


if __name__ == "__main__":
    main()
