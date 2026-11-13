"""Per-package ablation cost log in ``fyp_patches.ablation_costs``.

One document per package run. ``loops`` is one entry per model call, in order.
``totals`` sums those calls and records whether success landed by loop 5, by
loop 10, or not at all. Line counts stay null when the node does not write a
patch. Storage failures are logged and ignored.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from run_cost import response_usage


logger = logging.getLogger(__name__)
_STORAGE_ERRORS = (OSError, TypeError, ValueError, UnicodeError)
_RESPONSE_CHARS = 16_000
EARLY_LOOP = 5
LAST_LOOP = -1


def _storage_errors():
    try:
        from pymongo.errors import PyMongoError
    except ImportError:
        return _STORAGE_ERRORS
    return _STORAGE_ERRORS + (PyMongoError,)


def loop_outcome(success_loop: int | None, *, early: int = EARLY_LOOP, limit: int = 10) -> str:
    """Classify a successful loop. Loops 1-5 are ``max_5``; loops 6-10 are ``max_10``."""
    if isinstance(success_loop, bool) or not isinstance(success_loop, int):
        return "failed"
    if success_loop < 1 or success_loop > limit:
        return "failed"
    if success_loop <= early:
        return "max_5"
    return "max_10"


def record_loop(
    state: Mapping[str, Any],
    *,
    node: str,
    call: str,
    model: str | None = None,
    response: Any = None,
    error: str | None = None,
) -> None:
    """Append one model call for the package run identified by ``ablation_id``."""
    ablation_id = state.get("ablation_id")
    if not isinstance(ablation_id, str) or not ablation_id.strip():
        return
    try:
        document = _load(ablation_id)
        if document is None:
            document = _blank(state, ablation_id, model)
        usage = response_usage(response) if response is not None else {
            "prompt_tokens": None,
            "completion_tokens": None,
            "total_tokens": None,
            "cost": 0.0,
        }
        if model and not document.get("model"):
            document["model"] = model
        document["loops"].append({
            "loop": len(document["loops"]) + 1,
            "call": call,
            "node": node,
            "response": _response_text(response, error),
            "token_in": usage["prompt_tokens"],
            "token_out": usage["completion_tokens"],
            "total_tokens": usage["total_tokens"],
            "cost": usage["cost"],
            "lines_added": None,
            "lines_removed": None,
        })
        _save(document)
    except _storage_errors():
        logger.warning("Could not record ablation loop", exc_info=True)


def note_lines(state: Mapping[str, Any], diff: str) -> None:
    """Attach patch line counts to the latest loop. Other nodes stay null."""
    ablation_id = state.get("ablation_id")
    if not isinstance(ablation_id, str) or not ablation_id.strip():
        return
    if not isinstance(diff, str) or not diff.strip():
        return
    try:
        from cost_log import diff_line_counts

        document = _load(ablation_id)
        loops = (document or {}).get("loops") or []
        if not loops:
            return
        loops[-1].update(diff_line_counts(diff))
        _save(document)
    except _storage_errors():
        logger.warning("Could not record ablation line counts", exc_info=True)


def finish(
    state: Mapping[str, Any],
    *,
    success_loop: int | None = None,
    outcome: str | None = None,
    max_loop: int = 10,
) -> dict[str, Any] | None:
    """Write the package summary. ``success_loop`` of -1 means the last recorded call."""
    ablation_id = state.get("ablation_id")
    if not isinstance(ablation_id, str) or not ablation_id.strip():
        return None
    try:
        document = _load(ablation_id)
        if document is None:
            document = _blank(state, ablation_id, state.get("model_name"))
        total_loops = len(document.get("loops") or [])
        if success_loop == LAST_LOOP:
            success_loop = total_loops or None
        if outcome is None:
            outcome = loop_outcome(success_loop, limit=max_loop)
        document["max_loop"] = max_loop
        document["totals"] = _totals(document.get("loops") or [], outcome=outcome, success_loop=success_loop)
        _save(document)
        return document
    except _storage_errors():
        logger.warning("Could not finish ablation cost log", exc_info=True)
        return None


def _blank(state: Mapping[str, Any], ablation_id: str, model: str | None) -> dict[str, Any]:
    return {
        "ablation_id": ablation_id,
        "node": state.get("ablation_node"),
        "prompt_suffix": state.get("prompt_suffix"),
        "package_name": state.get("package_name"),
        "package_version": state.get("package_version"),
        "vulnerability_id": state.get("vulnerability_id"),
        "model": model or state.get("model_name"),
        "loops": [],
        "totals": None,
    }


def _totals(loops: list[dict[str, Any]], *, outcome: str, success_loop: int | None) -> dict[str, Any]:
    def total(key: str) -> int:
        amount = 0
        for item in loops:
            value = item.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                amount += value
        return amount

    def lines(key: str) -> int | None:
        present = [
            item.get(key) for item in loops
            if isinstance(item.get(key), int) and not isinstance(item.get(key), bool)
        ]
        if not present:
            return None
        return sum(present)

    cost = 0.0
    for item in loops:
        try:
            cost += float(item.get("cost") or 0)
        except (TypeError, ValueError):
            continue
    return {
        "total_loops": len(loops),
        "token_in": total("token_in"),
        "token_out": total("token_out"),
        "total_tokens": total("total_tokens"),
        "cost": cost,
        "lines_added": lines("lines_added"),
        "lines_removed": lines("lines_removed"),
        "success_loop": success_loop,
        "outcome": outcome,
    }


def _response_text(response: Any, error: str | None) -> str | None:
    if error:
        return str(error)[:_RESPONSE_CHARS]
    choices = getattr(response, "choices", None) or []
    if not choices:
        return None
    message = getattr(choices[0], "message", None)
    content = getattr(message, "content", None) if message is not None else None
    if isinstance(content, str):
        return content[:_RESPONSE_CHARS]
    return None


def _load(ablation_id: str) -> dict[str, Any] | None:
    document = _collection().find_one({"ablation_id": ablation_id}, {"_id": 0})
    if document is None:
        return None
    if not isinstance(document, dict) or not isinstance(document.get("loops"), list):
        raise ValueError("ablation cost log is not a loop list")
    return document


def _save(document: dict[str, Any]) -> None:
    _collection().replace_one({"ablation_id": document["ablation_id"]}, document, upsert=True)


def _collection():
    from db import _COL_ABLATION, _get_db

    return _get_db()[_COL_ABLATION]
