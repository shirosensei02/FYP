"""Config-backed catalog for the supported patch-generator/evaluator pair."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any


_MODELS_PATH = Path(__file__).resolve().parent / "config" / "models.json"
_PATCH_EVALUATOR_IDS = {
    "openai/gpt-5.3-codex",
    "anthropic/claude-sonnet-5",
}
SONNET = "anthropic/claude-sonnet-5"
CODEX = "openai/gpt-5.3-codex"
STAGE_MODELS = {
    "locator": SONNET,
    "oracle": SONNET,
    "patch": CODEX,
    "adversarial": SONNET,
}


def patch_evaluator_models() -> tuple[str, ...]:
    """Return the supported pair in the order declared by ``models.json``."""
    try:
        configured = json.loads(_MODELS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        configured = []
    return tuple(
        item["id"]
        for item in configured
        if isinstance(item, dict) and item.get("id") in _PATCH_EVALUATOR_IDS
    )


def canonical_model_id(model: str | None) -> str:
    """Match direct-provider and OpenRouter spellings for the same model."""
    value = (model or "").strip().lower()
    for provider in ("openai/", "anthropic/", "google/"):
        if value.startswith(provider):
            return value.removeprefix(provider)
    return value


def stage_model(state: Mapping[str, Any], stage: str) -> str | None:
    """Return the locked production model.

    An ablation run keeps the model stored on its state, so this returns None.
    """
    ablation_id = state.get("ablation_id")
    if isinstance(ablation_id, str) and ablation_id.strip():
        return None
    if stage not in STAGE_MODELS:
        raise ValueError(f"unknown pipeline stage: {stage}")
    return STAGE_MODELS[stage]


def evaluator_for(generator_model: str | None, requested_evaluator: str | None = None) -> str | None:
    """Select the other supported model; GPT-6 Luna is intentionally excluded."""
    generator = canonical_model_id(generator_model)
    for candidate in patch_evaluator_models():
        if canonical_model_id(candidate) != generator:
            return candidate
    return requested_evaluator
