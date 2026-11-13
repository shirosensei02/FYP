"""Resolve an ablation prompt file.

An empty suffix is the production prompt: the enriched locator, the enriched
oracle (``oracle.txt``), and the enriched patch. ``_CoT`` for the locator is
``locator.txt``, and ``_enriched`` for the oracle is ``oracle.txt``.
"""

from __future__ import annotations

from pathlib import Path


PROMPTS = Path(__file__).resolve().parent / "prompts"
SUFFIXES = ("_generic", "_enriched", "_CoT")
_FILES = {
    "locator": {
        "_generic": "locator_generic.txt",
        "_enriched": "locator_enriched.txt",
        "_CoT": "locator.txt",
    },
    "oracle": {
        "_generic": "oracle_generic.txt",
        "_enriched": "oracle.txt",
        "_CoT": "oracle_CoT.txt",
    },
    "patch": {
        "_generic": "patch_generic.txt",
        "_enriched": "patch_enriched.txt",
        "_CoT": "patch_CoT.txt",
    },
}
_DEFAULTS = {
    "locator": "locator_enriched.txt",
    "oracle": "oracle.txt",
    "patch": "patch_enriched.txt",
}
_TEXT_FIELDS = (
    "prompt_suffix",
    "ablation_id",
    "ablation_node",
    "cwe_id",
    "cwe_name",
    "cwe_description",
    "typical_sinks",
    "typical_control",
    "vulnerability_id",
)


def prompt_path(node: str, suffix: str | None = None) -> Path:
    """Return the prompt file for one node and one ablation suffix."""
    if node not in _FILES:
        raise ValueError(f"unknown prompt node: {node}")
    text = str(suffix or "").strip()
    if not text:
        return PROMPTS / _DEFAULTS[node]
    if text not in SUFFIXES:
        raise ValueError(f"prompt_suffix must be one of: {', '.join(SUFFIXES)}")
    return PROMPTS / _FILES[node][text]


def apply_run_config(state: dict, config: dict) -> None:
    """Copy ablation controls onto a run state. Blank values stay unset."""
    for key in _TEXT_FIELDS:
        value = config.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        state[key] = value.strip()
    for key in ("max_oracle_attempts", "max_locator_rounds", "locator_samples"):
        if config.get(key) is None:
            continue
        state[key] = int(config[key])
