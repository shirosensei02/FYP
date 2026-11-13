"""Append each model call to a per-attempt cost document in MongoDB.

One document per pipeline attempt in ``fyp_patches.attempt_costs``, keyed by
``run_attempt_id`` and attempt number. The header is the package, version, and
generator model. ``requests`` lists every model call that attempt made, in order.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from pymongo.errors import PyMongoError

from run_cost import response_usage


logger = logging.getLogger(__name__)
_STORAGE_ERRORS = (OSError, TypeError, ValueError, UnicodeError, PyMongoError)


def diff_line_counts(diff: str) -> dict[str, int]:
    """Count added and removed lines in a unified diff, ignoring file headers."""
    added = 0
    removed = 0
    for line in diff.splitlines():
        if line.startswith(("+++", "---", "diff --git")):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            removed += 1
    return {"lines_added": added, "lines_removed": removed}


def record_request(
    state: Mapping[str, Any],
    *,
    node: str,
    call: str,
    model: str | None = None,
    response: Any = None,
    error: str | None = None,
) -> None:
    """Append one model call to this attempt's cost document.

    Storage failures are logged and ignored so a database write cannot abort a run.
    """
    try:
        if state.get("ablation_id"):
            from ablation_cost import record_loop
            record_loop(state, node=node, call=call, model=model, response=response, error=error)
        located = _attempt(state)
        if located is None:
            return
        run_id, attempt_number = located
        document = _load(run_id, attempt_number)
        if document is None:
            document = _blank(state, run_id, attempt_number)
        if not document.get("model") and node == "patch_generation" and model:
            document["model"] = model
        usage = response_usage(response) if response is not None else {
            "prompt_tokens": None,
            "completion_tokens": None,
            "total_tokens": None,
            "cost": 0.0,
        }
        entry: dict[str, Any] = {
            "node": node,
            "call": call,
            "model": model,
            "prompt_tokens": usage["prompt_tokens"],
            "completion_tokens": usage["completion_tokens"],
            "total_tokens": usage["total_tokens"],
            "cost": usage["cost"],
            "lines_added": None,
            "lines_removed": None,
        }
        if error:
            entry["error"] = error
        document["requests"].append(entry)
        _refresh_totals(document)
        _save(document)
    except _STORAGE_ERRORS:
        logger.warning("Could not record model request cost", exc_info=True)


def note_written_lines(state: Mapping[str, Any], diff: str) -> None:
    """Attach added and removed line counts to the latest generation request."""
    if not isinstance(diff, str) or not diff.strip():
        return
    try:
        if state.get("ablation_id"):
            from ablation_cost import note_lines
            note_lines(state, diff)
        located = _attempt(state)
        if located is None:
            return
        document = _load(*located)
        if document is None:
            return
        requests = document.get("requests") or []
        if not requests:
            return
        last = requests[-1]
        if last.get("node") != "patch_generation" or last.get("lines_added") is not None:
            return
        last.update(diff_line_counts(diff))
        _refresh_totals(document)
        _save(document)
    except _STORAGE_ERRORS:
        logger.warning("Could not record patch line counts", exc_info=True)


def record_attempt_outcome(state: Mapping[str, Any], *, passed: bool) -> None:
    """Record whether this attempt succeeded once validation has decided."""
    try:
        located = _attempt(state)
        if located is None:
            return
        run_id, attempt_number = located
        document = _load(run_id, attempt_number)
        if document is None:
            document = _blank(state, run_id, attempt_number)
        document["totals"]["outcome"] = "success" if passed else "failed"
        _save(document)
    except _STORAGE_ERRORS:
        logger.warning("Could not record attempt outcome", exc_info=True)


def _attempt(state: Mapping[str, Any]) -> tuple[str, int] | None:
    run_id = state.get("run_attempt_id")
    if not isinstance(run_id, str) or not run_id.strip():
        return None
    raw = state.get("retry_count") or 0
    if isinstance(raw, bool):
        return None
    try:
        attempt_number = int(raw) + 1
    except (TypeError, ValueError):
        return None
    if attempt_number < 1:
        return None
    return run_id, attempt_number


def _blank(state: Mapping[str, Any], run_id: str, attempt_number: int) -> dict[str, Any]:
    return {
        "key": f"{run_id}-{attempt_number}",
        "run_attempt_id": run_id,
        "attempt_number": attempt_number,
        "package_name": state.get("package_name"),
        "package_version": state.get("package_version"),
        "model": state.get("model_name") or state.get("generation_model_used"),
        "requests": [],
        "totals": _totals([], outcome=None),
    }


def _refresh_totals(document: dict[str, Any]) -> None:
    previous = document.get("totals") or {}
    document["totals"] = _totals(document.get("requests") or [], outcome=previous.get("outcome"))


def _totals(requests: list[dict[str, Any]], *, outcome: str | None) -> dict[str, Any]:
    def total(key: str) -> int:
        amount = 0
        for item in requests:
            value = item.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                amount += value
        return amount

    cost = 0.0
    for item in requests:
        try:
            cost += float(item.get("cost") or 0)
        except (TypeError, ValueError):
            continue
    return {
        "prompt_tokens": total("prompt_tokens"),
        "completion_tokens": total("completion_tokens"),
        "total_tokens": total("total_tokens"),
        "cost": cost,
        "lines_added": total("lines_added"),
        "lines_removed": total("lines_removed"),
        "outcome": outcome,
    }


def _load(run_id: str, attempt_number: int) -> dict[str, Any] | None:
    document = _collection().find_one(
        {"run_attempt_id": run_id, "attempt_number": attempt_number},
        {"_id": 0},
    )
    if document is None:
        return None
    if not isinstance(document, dict) or not isinstance(document.get("requests"), list):
        raise ValueError("cost log is not a request list")
    return document


def _save(document: dict[str, Any]) -> None:
    _collection().replace_one(
        {
            "run_attempt_id": document["run_attempt_id"],
            "attempt_number": document["attempt_number"],
        },
        document,
        upsert=True,
    )


def _collection():
    from db import _COL_COSTS, _get_db

    return _get_db()[_COL_COSTS]
