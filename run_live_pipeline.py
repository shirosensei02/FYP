from __future__ import annotations

import argparse
import json
from typing import Any

from package_input import package_input
from patch_generation import patch_generation
from vulnerability_detection import vulnerability_detection


def _build_mock_vulnerability(package_name: str, package_version: str) -> dict[str, Any]:
    return {
        "id": "MOCK-CVE-0001",
        "severity": "high",
        "package": package_name,
        "installed_version": package_version,
        "fixed_version": None,
        "description": "Injected mock vulnerability for live patch-generation testing.",
        "scanner": "mock",
        "aliases": [],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the package_input -> vulnerability_detection -> patch_generation flow.")
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--package-version", required=True)
    parser.add_argument("--model-provider", default="mock", choices=["mock", "openai", "anthropic"])
    parser.add_argument("--model-name")
    parser.add_argument("--patch-scope", default="single", choices=["single", "all"])
    parser.add_argument("--inject-mock-vulnerability", action="store_true")
    args = parser.parse_args()

    state: dict[str, Any] = {
        "package_name": args.package_name,
        "package_version": args.package_version,
        "model_provider": args.model_provider,
        "patch_scope": args.patch_scope,
    }
    if args.model_name:
        state["model_name"] = args.model_name

    state.update(package_input(state))
    if state.get("errors"):
        print(json.dumps({"stage": "package_input", "state": state}, indent=2))
        return

    state.update(vulnerability_detection(state))

    if args.inject_mock_vulnerability and not state.get("current_vulnerabilities"):
        mock_vulnerability = _build_mock_vulnerability(args.package_name, args.package_version)
        state["vulnerabilities"] = [mock_vulnerability]
        state["current_vulnerabilities"] = [mock_vulnerability]

    state.update(patch_generation(state))
    print(json.dumps(state, indent=2))


if __name__ == "__main__":
    main()
