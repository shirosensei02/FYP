"""Run the patch graph once per sample.

Batching separate from graph. 
Each sample is a fresh state for one package, version and model, and owns its own retries
Runner records each result and cost, stops if next run exceeds cost cap
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from model_catalog import patch_evaluator_models


load_dotenv(Path(__file__).resolve().parent / ".env")
DEFAULT_CONFIG = Path(__file__).resolve().parent / "config" / "batch.json"

Package = tuple[str, str]
_PROVIDERS = ("mock", "openai", "anthropic", "gemini", "openrouter")
_PATCH_SCOPES = ("single", "all")


def parse_package(spec: str) -> Package:
    """Parse ``name@version``. Scoped packages use ``@scope/name@version``."""
    name, separator, version = spec.rpartition("@")
    if not separator or not name or not version:
        raise ValueError(
            f"package must be name@version (scoped names use @scope/name@version): {spec}"
        )
    return name, version


def should_start_run(spent: float, completed: int, cost_cap: float) -> bool:
    """Return whether another fresh sample fits under the cap.

    The first sample always starts. After that, a sample starts only while the
    money already spent is under the cap and the average completed sample would
    still leave the next one inside the cap.
    """
    if completed <= 0:
        return True
    if spent >= cost_cap:
        return False
    average = spent / completed
    return spent + average <= cost_cap


def _fresh_state(
    package_name: str,
    package_version: str,
    *,
    model_provider: str,
    model_name: str,
    max_retries: int,
    patch_scope: str,
) -> dict[str, Any]:
    return {
        "package_name": package_name,
        "package_version": package_version,
        "model_provider": model_provider,
        "model_name": model_name,
        "patch_scope": patch_scope,
        "retry_count": 0,
        "max_retries": max_retries,
        "errors": [],
        "run_cost": 0.0,
    }


def _require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def load_batch_config(path: str | Path) -> dict[str, Any]:
    """Read the batch schedule.

    ``packages`` is an ordered list. Each item sets ``package``
    (``name@version``), ``num_runs``, and ``model``. The same package and
    version may appear more than once with a different model. ``cost_cap``
    applies to the whole file. Entries run in list order.
    """
    config_path = Path(path)
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"batch config not found: {config_path}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"batch config is not valid JSON: {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("batch config must be a JSON object")

    cost_cap = data.get("cost_cap")
    if isinstance(cost_cap, bool) or not isinstance(cost_cap, (int, float)):
        raise ValueError("cost_cap must be a number")
    if cost_cap < 0:
        raise ValueError("cost_cap must be zero or positive")

    model_provider = data.get("model_provider", "openrouter")
    if model_provider not in _PROVIDERS:
        raise ValueError(f"model_provider must be one of: {', '.join(_PROVIDERS)}")
    patch_scope = data.get("patch_scope", "single")
    if patch_scope not in _PATCH_SCOPES:
        raise ValueError("patch_scope must be 'single' or 'all'")
    max_retries = _require_int(data.get("max_retries", 1), "max_retries")
    if max_retries < 0:
        raise ValueError("max_retries must be zero or positive")

    packages = data.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("packages must be a non-empty list")

    allowed_models = patch_evaluator_models()
    jobs: list[dict[str, Any]] = []
    for index, entry in enumerate(packages):
        label = f"packages[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"{label} must be an object with package, num_runs, and model")
        spec = entry.get("package")
        if not isinstance(spec, str):
            raise ValueError(f"{label} package must be name@version")
        label = spec
        package_name, package_version = parse_package(spec)
        num_runs = _require_int(entry.get("num_runs"), f"{spec} num_runs")
        if num_runs < 1:
            raise ValueError(f"{spec} num_runs must be at least 1")
        model = entry.get("model")
        if not isinstance(model, str) or not model.strip():
            raise ValueError(f"{spec} model must be a model id")
        if model_provider == "openrouter" and model not in allowed_models:
            raise ValueError(f"{spec} model must be one of: {', '.join(allowed_models)}")
        jobs.append(
            {
                "package_name": package_name,
                "package_version": package_version,
                "num_runs": num_runs,
                "model": model,
            }
        )

    return {
        "cost_cap": float(cost_cap),
        "model_provider": model_provider,
        "max_retries": max_retries,
        "patch_scope": patch_scope,
        "jobs": jobs,
    }


def run_batch(
    jobs: Sequence[Mapping[str, Any]],
    cost_cap: float,
    *,
    model_provider: str = "openrouter",
    max_retries: int = 1,
    patch_scope: str = "single",
    invoke: Callable[[dict], dict] | None = None,
) -> dict[str, Any]:
    """Invoke the patch graph once per sample, stopping at the cost cap."""
    if not jobs:
        raise ValueError("at least one package is required")
    if cost_cap < 0:
        raise ValueError("cost_cap must be zero or positive")

    if invoke is None:
        from graph import graph

        invoke = graph.invoke

    schedule = [
        (job["package_name"], job["package_version"], run_index, job["model"])
        for job in jobs
        for run_index in range(int(job["num_runs"]))
    ]
    completed: list[dict[str, Any]] = []
    spent = 0.0
    stopped_reason = None

    for package_name, package_version, run_index, model_name in schedule:
        if not should_start_run(spent, len(completed), cost_cap):
            stopped_reason = "cost_cap"
            break
        print(
            f"starting {package_name}@{package_version} "
            f"run={run_index} model={model_name}",
            flush=True,
        )
        state = _fresh_state(
            package_name,
            package_version,
            model_provider=model_provider,
            model_name=model_name,
            max_retries=max_retries,
            patch_scope=patch_scope,
        )
        try:
            final = invoke(state) or {}
            error = None
        except Exception as exc:
            final = {}
            error = f"{type(exc).__name__}: {exc}"
        cost = float(final.get("run_cost") or 0)
        spent += cost
        completed.append(
            {
                "package_name": package_name,
                "package_version": package_version,
                "model_name": model_name,
                "run_index": run_index,
                "classification": final.get("classification"),
                "classification_reason": final.get("classification_reason"),
                "retry_count": final.get("retry_count", 0),
                "run_cost": cost,
                "spent": spent,
                "error": error,
            }
        )
        print(
            f"finished {package_name}@{package_version} "
            f"run={run_index} classification={final.get('classification')} "
            f"cost={cost:.6f} spent={spent:.6f}",
            flush=True,
        )

    return {
        "runs": completed,
        "spent": spent,
        "scheduled": len(schedule),
        "stopped_reason": stopped_reason,
    }


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the patch graph from a JSON batch config until the cost cap."
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG,
        help="Path to the batch JSON config (default: config/batch.json)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        config = load_batch_config(args.config)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    summary = run_batch(
        config["jobs"],
        config["cost_cap"],
        model_provider=config["model_provider"],
        max_retries=config["max_retries"],
        patch_scope=config["patch_scope"],
    )
    for run in summary["runs"]:
        print(
            f"{run['package_name']}@{run['package_version']} "
            f"run={run['run_index']} model={run['model_name']} "
            f"classification={run['classification']} "
            f"retries={run['retry_count']} "
            f"cost={run['run_cost']:.6f} spent={run['spent']:.6f}"
        )
        if run["error"]:
            print(f"  error: {run['error']}")
    print(
        f"completed={len(summary['runs'])} scheduled={summary['scheduled']} "
        f"spent={summary['spent']:.6f} stopped={summary['stopped_reason'] or 'finished'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
