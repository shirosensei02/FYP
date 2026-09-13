from __future__ import annotations

import argparse
import json
from typing import Any

from graph import graph


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the complete package remediation pipeline and persist each outcome.")
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--package-version", required=True)
    parser.add_argument(
        "--model-provider",
        default="mock",
        choices=["mock", "openai", "anthropic", "gemini", "openrouter"],
    )
    parser.add_argument("--model-name")
    parser.add_argument("--patch-scope", default="single", choices=["single", "all"])
    args = parser.parse_args()

    state: dict[str, Any] = {
        "package_name": args.package_name,
        "package_version": args.package_version,
        "model_provider": args.model_provider,
        "patch_scope": args.patch_scope,
        "errors": [],
    }
    if args.model_name:
        state["model_name"] = args.model_name

    result = graph.invoke(state)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
