from __future__ import annotations

import argparse
import json
import os
from typing import Any

from graph import graph  # noqa: F401  (imported first so its dotenv-loading deps run before os.getenv defaults below)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the complete package remediation pipeline and persist each outcome.")
    parser.add_argument("--package-name", default=os.getenv("PACKAGE_NAME"),
                        help="Falls back to PACKAGE_NAME in .env")
    parser.add_argument("--package-version", default=os.getenv("PACKAGE_VERSION"),
                        help="Falls back to PACKAGE_VERSION in .env")
    parser.add_argument(
        "--model-provider",
        default=os.getenv("MODEL_PROVIDER", "mock"),
        choices=["mock", "openai", "anthropic", "gemini", "openrouter"],
        help="Falls back to MODEL_PROVIDER in .env",
    )
    parser.add_argument("--model-name", default=os.getenv("MODEL_NAME"),
                        help="Falls back to MODEL_NAME in .env")
    parser.add_argument("--patch-scope", default=os.getenv("PATCH_SCOPE", "single"), choices=["single", "all"])
    args = parser.parse_args()
    if not args.package_name or not args.package_version:
        parser.error("--package-name/--package-version are required (pass the flag, or set "
                     "PACKAGE_NAME/PACKAGE_VERSION in .env)")

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
