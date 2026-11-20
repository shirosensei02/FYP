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
from prompt_variant import SUFFIXES


load_dotenv(Path(__file__).resolve().parent / ".env")
DEFAULT_CONFIG = Path(__file__).resolve().parent / "config" / "batch.json"

Package = tuple[str, str]
_PROVIDERS = ("mock", "openai", "anthropic", "gemini", "openrouter")
_PATCH_SCOPES = ("single", "all")
# Optional per-entry prompt context (the enriched prompts read these from state).
_EXTRA_FIELDS = ("cwe_id", "cwe_name", "cwe_description", "typical_sinks", "typical_control")


def parse_package(spec: str) -> Package:
    """Parse ``name@version``. Scoped packages use ``@scope/name@version``."""
    name, separator, version = spec.rpartition("@")
    if not separator or not name or not version:
        raise ValueError(
            f"package must be name@version (scoped names use @scope/name@version): {spec}"
        )
    return name, version


def _clip(text: str, limit: int = 240) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _execution_log(execution: Any, label: str) -> list[str]:
    """Return the captured Docker output for one oracle sandbox."""
    if not isinstance(execution, dict):
        return []
    stdout = str(execution.get("stdout") or "").strip()
    stderr = str(execution.get("stderr") or "").strip()
    evidence = str(execution.get("evidence") or "").strip()
    body = "\n".join(part for part in (stderr, stdout) if part)
    if not body:
        body = evidence
    if not body:
        return []
    return [f"{label} log:", *body.splitlines()]


def oracle_failure_summaries(state: Mapping[str, Any]) -> list[str]:
    """Compact fail reasons from oracle authoring and the locked-oracle check."""
    lines: list[str] = []
    for attempt in state.get("oracle_attempts") or []:
        if not isinstance(attempt, dict):
            continue
        generation = attempt.get("generation") if isinstance(attempt.get("generation"), dict) else {}
        validation = attempt.get("validation") if isinstance(attempt.get("validation"), dict) else {}
        generation_status = generation.get("status")
        validation_status = validation.get("status")
        if generation_status in {"generated", "accepted"} and validation_status == "VALID":
            continue
        if generation_status is None and validation_status is None:
            continue
        vulnerable = validation.get("vulnerable") if isinstance(validation.get("vulnerable"), dict) else {}
        fixed = validation.get("fixed") if isinstance(validation.get("fixed"), dict) else {}
        sides = ""
        if vulnerable.get("status") or fixed.get("status"):
            sides = (
                f" vulnerable={vulnerable.get('status') or 'not-run'}"
                f" fixed={fixed.get('status') or 'not-run'}"
            )
        status = validation_status or generation_status or "unknown"
        detail = validation.get("reason") or generation.get("explanation") or ""
        separator = " — " if detail else ""
        lines.append(_clip(
            f"oracle attempt {attempt.get('attempt_number', '?')}: {status}{sides}{separator}{detail}"
        ))
        lines.extend(_execution_log(vulnerable, "vulnerable"))
        lines.extend(_execution_log(fixed, "maintainer"))

    patch_oracle = state.get("generated_patch_oracle_validation")
    if isinstance(patch_oracle, dict) and patch_oracle.get("status") in {
        "SECURITY_FAIL", "REGRESSION", "INCONCLUSIVE",
    }:
        detail = patch_oracle.get("reason") or ""
        separator = " — " if detail else ""
        lines.append(_clip(f"patch oracle: {patch_oracle.get('status')}{separator}{detail}"))
        lines.extend(_execution_log(patch_oracle.get("execution"), "patch oracle"))
    return lines


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
    prompt_suffix: str = "",
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    state: dict[str, Any] = {
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
    if prompt_suffix:
        state["prompt_suffix"] = prompt_suffix
    state.update({k: v for k, v in (extra or {}).items() if k in _EXTRA_FIELDS})
    return state


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
        prompt_suffix = str(entry.get("prompt_suffix") or "").strip()
        if prompt_suffix and prompt_suffix not in SUFFIXES:
            raise ValueError(f"{spec} prompt_suffix must be one of: {', '.join(SUFFIXES)}")
        jobs.append(
            {
                "package_name": package_name,
                "package_version": package_version,
                "num_runs": num_runs,
                "model": model,
                "prompt_suffix": prompt_suffix,
                "extra": {k: entry[k] for k in _EXTRA_FIELDS if entry.get(k)},
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
    results_path: str | Path | None = None,
) -> dict[str, Any]:
    """Invoke the patch graph once per sample, stopping at the cost cap.

    When ``results_path`` is set, each finished run is appended to it as one
    JSON line, and runs already recorded there (same package, version, model,
    prompt suffix and run index) are skipped, so an interrupted batch resumes.
    """
    if not jobs:
        raise ValueError("at least one package is required")
    if cost_cap < 0:
        raise ValueError("cost_cap must be zero or positive")

    if invoke is None:
        from graph import graph

        invoke = graph.invoke

    schedule = [
        (
            job["package_name"], job["package_version"], run_index, job["model"],
            job.get("prompt_suffix") or "", job.get("extra") or {},
        )
        for job in jobs
        for run_index in range(int(job["num_runs"]))
    ]
    completed: list[dict[str, Any]] = []
    spent = 0.0
    stopped_reason = None

    def _key(item: Mapping[str, Any]) -> tuple:
        return (
            item.get("package_name"), item.get("package_version"), item.get("run_index"),
            item.get("model_name"), item.get("prompt_suffix") or "",
        )

    done: set[tuple] = set()
    if results_path and Path(results_path).is_file():
        for line in Path(results_path).read_text(encoding="utf-8").splitlines():
            try:
                done.add(_key(json.loads(line)))
            except json.JSONDecodeError:
                continue

    for package_name, package_version, run_index, model_name, prompt_suffix, extra in schedule:
        if (package_name, package_version, run_index, model_name, prompt_suffix) in done:
            continue
        if not should_start_run(spent, len(completed), cost_cap):
            stopped_reason = "cost_cap"
            break
        print(
            f"starting {package_name}@{package_version} "
            f"run={run_index} model={model_name} prompt={prompt_suffix or 'default'}",
            flush=True,
        )
        state = _fresh_state(
            package_name,
            package_version,
            model_provider=model_provider,
            model_name=model_name,
            max_retries=max_retries,
            patch_scope=patch_scope,
            prompt_suffix=prompt_suffix,
            extra=extra,
        )
        try:
            final = invoke(state) or {}
            error = None
        except Exception as exc:
            final = {}
            error = f"{type(exc).__name__}: {exc}"
        cost = float(final.get("run_cost") or 0)
        spent += cost
        oracle_failures = oracle_failure_summaries(final)
        evaluation = final.get("final_evaluation")
        record = {
                "package_name": package_name,
                "package_version": package_version,
                "model_name": model_name,
                "prompt_suffix": prompt_suffix,
                "cwe_id": extra.get("cwe_id"),
                "genuine_fix": (final.get("adversarial_evaluation") or {}).get("genuine_fix"),
                "adversarial_status": (final.get("adversarial_evaluation") or {}).get("status"),
                "evaluator_model": (final.get("adversarial_evaluation") or {}).get("evaluator_model"),
                "oracle_status": (final.get("generated_patch_oracle_validation") or {}).get("status"),
                "run_index": run_index,
                "final_category": (
                    evaluation.get("category") if isinstance(evaluation, Mapping) else None
                ) or "inconclusive",
                "classification": final.get("classification"),
                "classification_reason": final.get("classification_reason"),
                "oracle_failures": oracle_failures,
                "retry_count": final.get("retry_count", 0),
                "run_cost": cost,
                "spent": spent,
                "error": error,
        }
        completed.append(record)
        if results_path:
            with Path(results_path).open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str) + "\n")
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
    parser.add_argument(
        "--results",
        default=None,
        help="JSONL file that records each finished run and lets a rerun resume",
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
        results_path=args.results,
    )
    for run in summary["runs"]:
        print(
            f"{run['package_name']}@{run['package_version']} "
            f"run={run['run_index']} model={run['model_name']} "
            f"classification={run['classification']} "
            f"retries={run['retry_count']} "
            f"cost={run['run_cost']:.6f} spent={run['spent']:.6f}"
        )
        for failure in run.get("oracle_failures") or []:
            print(f"  {failure}")
        if run["error"]:
            print(f"  error: {run['error']}")
    print(
        f"completed={len(summary['runs'])} scheduled={summary['scheduled']} "
        f"spent={summary['spent']:.6f} stopped={summary['stopped_reason'] or 'finished'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
