"""Run one ablation node across every package in batch_config.json.

The config chooses the node, the prompt suffix, and the loop cap. The cap is
always 10. A locator outcome is ``located/total`` expected files. An oracle or
patch success on loops 1-5 is recorded as max_5, and a success on loops 6-10
is recorded as max_10. Each package is logged in fyp_patches.ablation_costs and
a failure does not stop the remaining packages.

  python isolated_runners/batch_runner.py
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ablation_cost import finish
from locator_answer import load_answer_key, located_file_ratio
from prompt_variant import SUFFIXES


CONFIG_PATH = Path(__file__).resolve().parent / "batch_config.json"
ANSWER_KEY_PATH = Path(__file__).resolve().parent / "locator_answer_key.json"
NODES = ("locator", "oracle", "patch")


def load_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Read and check the batch file."""
    if not path.is_file():
        raise ValueError(f"missing batch config: {path}")
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("batch_config.json must be a JSON object")
    node = str(config.get("node") or "").strip()
    suffix = str(config.get("prompt_suffix") or "").strip()
    if node not in NODES:
        raise ValueError(f"node must be one of: {', '.join(NODES)}")
    if suffix not in SUFFIXES:
        raise ValueError(f"prompt_suffix must be one of: {', '.join(SUFFIXES)}")
    packages = config.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("packages must be a non-empty list")
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("each package must be an object")
        if not str(package.get("package_name") or "").strip() or not str(package.get("package_version") or "").strip():
            raise ValueError("each package needs package_name and package_version")
    try:
        max_loop = int(config.get("max_loop") or 10)
    except (TypeError, ValueError):
        raise ValueError("max_loop must be an integer") from None
    if max_loop < 1:
        raise ValueError("max_loop must be at least 1")
    config["node"] = node
    config["prompt_suffix"] = suffix
    config["max_loop"] = max_loop
    return config


def _runner(
    node: str,
    run_locator: Callable[[dict], dict] | None,
    run_oracle: Callable[[dict], dict] | None,
    run_patch: Callable[[dict], dict] | None,
) -> Callable[[dict], dict]:
    if node == "locator":
        if run_locator is None:
            from isolated_runners.isolate_locator import run as run_locator
        return run_locator
    if node == "oracle":
        if run_oracle is None:
            from isolated_runners.isolate_oracle import run as run_oracle
        return run_oracle
    if run_patch is None:
        from isolated_runners.isolate_patch_gen import run as run_patch
    return run_patch


def run_batch(
    config: dict[str, Any],
    *,
    run_locator: Callable[[dict], dict] | None = None,
    run_oracle: Callable[[dict], dict] | None = None,
    run_patch: Callable[[dict], dict] | None = None,
    answer_key: dict | None = None,
) -> list[dict[str, Any]]:
    """Run every package. One package failure is recorded and the batch continues."""
    node = config["node"]
    runner = _runner(node, run_locator, run_oracle, run_patch)
    if answer_key is None and node == "locator":
        answer_key = load_answer_key(ANSWER_KEY_PATH)
    results = []
    for package in config["packages"]:
        package_config = _package_config(config, package)
        print(
            f"\n===== {package_config['package_name']}@{package_config['package_version']} "
            f"{node} {config['prompt_suffix']} =====",
            flush=True,
        )
        try:
            result = runner(package_config)
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            print(f"ERROR: {message}", flush=True)
            result = {"ok": False, "error": message, "state": _state_from(package_config), "success_loop": None}
        results.append(_record(config, package_config, result, answer_key or {}))
    return results


def _package_config(config: dict[str, Any], package: dict[str, Any]) -> dict[str, Any]:
    merged = dict(package)
    merged["model_provider"] = config.get("model_provider") or package.get("model_provider") or "openrouter"
    merged["model_name"] = config.get("model_name") or package.get("model_name") or ""
    merged["prompt_suffix"] = config["prompt_suffix"]
    merged["ablation_node"] = config["node"]
    merged["ablation_id"] = (
        f"{config['node']}-{config['prompt_suffix']}-"
        f"{package.get('package_name')}-{package.get('package_version')}-{uuid.uuid4().hex[:8]}"
    )
    if config["node"] == "oracle":
        merged["max_oracle_attempts"] = config["max_loop"]
    if config["node"] == "patch":
        merged["max_patch_attempts"] = config["max_loop"]
    if config["node"] == "locator":
        merged["max_locator_rounds"] = config["max_loop"]
        merged["locator_samples"] = 1
    return merged


def _state_from(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "ablation_id": config.get("ablation_id"),
        "ablation_node": config.get("ablation_node"),
        "prompt_suffix": config.get("prompt_suffix"),
        "package_name": config.get("package_name"),
        "package_version": config.get("package_version"),
        "vulnerability_id": config.get("vulnerability_id"),
        "model_name": config.get("model_name"),
    }


def _record(
    config: dict[str, Any],
    package_config: dict[str, Any],
    result: dict[str, Any],
    answer_key: dict,
) -> dict[str, Any]:
    state = result.get("state") or _state_from(package_config)
    for key, value in _state_from(package_config).items():
        if not state.get(key):
            state[key] = value
    success_loop, outcome = _success(config["node"], result, package_config, answer_key)
    document = finish(
        state,
        success_loop=success_loop,
        outcome=outcome,
        max_loop=config["max_loop"],
    )
    totals = (document or {}).get("totals") or {}
    print(
        f"outcome: {totals.get('outcome') or outcome} "
        f"loops={totals.get('total_loops')} "
        f"token_in={totals.get('token_in')} "
        f"token_out={totals.get('token_out')} "
        f"cost={totals.get('cost')}",
        flush=True,
    )
    return {"package": package_config["package_name"], "outcome": totals.get("outcome") or outcome, "totals": totals}


def _success(
    node: str,
    result: dict[str, Any],
    package_config: dict[str, Any],
    answer_key: dict,
) -> tuple[int | None, str | None]:
    if node in {"oracle", "patch"}:
        if result.get("ok"):
            return result.get("success_loop"), None
        return None, None
    key = (str(package_config.get("package_name") or ""), str(package_config.get("package_version") or ""))
    expected = answer_key.get(key) or []
    state = result.get("state") or {}
    if not result.get("ok"):
        state = {}
    ratio = located_file_ratio(state, expected)
    if ratio is None:
        print(f"answer key: no locations for {key[0]}@{key[1]}", flush=True)
        return None, "unscored"
    return None, ratio


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        config = load_config()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        sys.exit(f"ERROR: {exc}")
    run_batch(config)


if __name__ == "__main__":
    main()
