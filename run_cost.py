"""Read the dollar cost reported on an LLM response and add it to a run."""

from __future__ import annotations

from typing import Any


def response_cost(response: Any) -> float:
    """Return the USD cost attached to a provider response, or 0 when it is absent."""
    found = _find_cost(response)
    return found if found is not None else 0.0


def response_usage(response: Any) -> dict[str, Any]:
    """Return token counts and USD cost from a provider response.

    Missing token counts stay None. Cost is 0 when the provider omits it.
    """
    usage = _usage_mapping(getattr(response, "usage", None))
    if not usage and isinstance(response, dict):
        usage = _usage_mapping(response.get("usage"))
    prompt = _coerce_int(usage.get("prompt_tokens"))
    completion = _coerce_int(usage.get("completion_tokens"))
    total = _coerce_int(usage.get("total_tokens"))
    if total is None and prompt is not None and completion is not None:
        total = prompt + completion
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
        "cost": response_cost(response),
    }


def add_run_cost(state: dict, amount: float) -> dict:
    """Return the graph update that adds one call's cost to the running total."""
    return {"run_cost": float(state.get("run_cost") or 0) + float(amount)}


def _coerce_int(raw: Any) -> int | None:
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, float) and raw.is_integer():
        return int(raw)
    if isinstance(raw, str):
        text = raw.strip()
        if text.isdigit() or (text.startswith("-") and text[1:].isdigit()):
            return int(text)
    return None


def _usage_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    mapped: dict[str, Any] = {}
    dumper = getattr(value, "model_dump", None)
    if callable(dumper):
        try:
            dumped = dumper()
        except Exception:
            dumped = None
        if isinstance(dumped, dict):
            mapped.update(dumped)
    for key in ("prompt_tokens", "completion_tokens", "total_tokens", "cost"):
        if key not in mapped and hasattr(value, key):
            mapped[key] = getattr(value, key)
    extra = getattr(value, "model_extra", None)
    if isinstance(extra, dict):
        for key in ("prompt_tokens", "completion_tokens", "total_tokens", "cost"):
            if key not in mapped and key in extra:
                mapped[key] = extra[key]
    return mapped


def _coerce_cost(raw: Any) -> float | None:
    if raw is None or isinstance(raw, bool):
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _find_cost(payload: Any, *, allow_dump: bool = True) -> float | None:
    if payload is None:
        return None
    if isinstance(payload, dict):
        found = _coerce_cost(payload.get("cost"))
        if found is not None:
            return found
        for key in ("model_extra", "usage"):
            found = _find_cost(payload.get(key), allow_dump=False)
            if found is not None:
                return found
        return None

    found = _coerce_cost(getattr(payload, "cost", None))
    if found is not None:
        return found
    extra = getattr(payload, "model_extra", None)
    if isinstance(extra, dict):
        found = _find_cost(extra, allow_dump=False)
        if found is not None:
            return found
    usage = getattr(payload, "usage", None)
    if usage is not None and usage is not payload:
        found = _find_cost(usage, allow_dump=allow_dump)
        if found is not None:
            return found
    if allow_dump:
        dumper = getattr(payload, "model_dump", None)
        if callable(dumper):
            try:
                dumped = dumper()
            except Exception:
                dumped = None
            if isinstance(dumped, dict):
                return _find_cost(dumped, allow_dump=False)
    return None
