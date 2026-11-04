"""One oracle-generation call, with the raw model response printed.

Usage (from the FYP directory):

    python temp_oracle.py
    python temp_oracle.py --package pidusage --version 1.1.4 --model anthropic/claude-sonnet-5
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from og_patch_resolution import og_patch_resolution
from oracle_generation import OPENROUTER_BASE_URL, _parse_candidate, _prompt
from package_input import package_input
from vulnerability_detection import vulnerability_detection
from vulnerability_localization import vulnerability_localization


load_dotenv(Path(__file__).resolve().parent / ".env")


def _prepare(package: str, version: str, model: str) -> dict:
    state = {
        "package_name": package,
        "package_version": version,
        "model_provider": "openrouter",
        "model_name": model,
        "patch_scope": "single",
        "errors": [],
        "run_cost": 0.0,
    }
    for name, step in (
        ("package_input", package_input),
        ("vulnerability_detection", vulnerability_detection),
        ("og_patch_resolution", og_patch_resolution),
        ("vulnerability_localization", vulnerability_localization),
    ):
        print(f"preparing {name}...", flush=True)
        state.update(step(state))
        errors = state.get("errors") or []
        if errors:
            print(f"  errors: {errors[-1]}", flush=True)
    return state


def _dump(value) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, indent=2, ensure_ascii=False, default=str)


def main() -> int:
    parser = argparse.ArgumentParser(description="Print one raw oracle-generation response.")
    parser.add_argument("--package", default="pidusage")
    parser.add_argument("--version", default="1.1.4")
    parser.add_argument("--model", default="anthropic/claude-sonnet-5")
    args = parser.parse_args()

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("OPENROUTER_API_KEY is not set")
        return 1

    state = _prepare(args.package, args.version, args.model)
    prompt = _prompt(state)
    print(f"prompt characters: {len(prompt)}", flush=True)

    client = OpenAI(
        api_key=api_key,
        base_url=os.getenv("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL),
        timeout=180.0,
    )
    try:
        response = client.chat.completions.create(
            model=args.model,
            temperature=0,
            max_tokens=12_000,
            response_format={"type": "json_object"},
            extra_body={"reasoning": {"enabled": False, "exclude": True}},
            messages=[
                {"role": "system", "content": "Return one JSON oracle object and nothing else."},
                {"role": "user", "content": prompt},
            ],
        )
    except Exception as exc:
        print(f"request failed: {type(exc).__name__}: {exc}")
        return 1

    choice = (getattr(response, "choices", None) or [None])[0]
    message = getattr(choice, "message", None) if choice else None
    content = getattr(message, "content", None) if message else None
    refusal = getattr(message, "refusal", None) if message else None
    finish = getattr(choice, "finish_reason", None) if choice else None
    text = content.strip() if isinstance(content, str) else ""
    parsed = _parse_candidate(text, 1, args.model)

    print(f"finish_reason: {finish}")
    print(f"content is None: {content is None}")
    print(f"content characters: {len(content) if isinstance(content, str) else 0}")
    print(f"refusal: {refusal!r}")
    print(f"parsed: {parsed if isinstance(parsed, str) else parsed.get('status')}")
    print("\n--- message ---")
    print(_dump(message) if message is not None else "(no message)")
    print("\n--- choice ---")
    print(_dump(choice) if choice is not None else "(no choice)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
