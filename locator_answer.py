"""Score locator output against the files in the answer key.

The answer key does not store diff bodies. The batch score is how many of the
expected files were located, written as ``located/total``. Extra files are
ignored. An empty location list means the package has not been filled in yet.
``match_locations`` still checks a function or changed line when a caller asks
for that stricter hit.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_answer_key(path: Path) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Map ``(package, version)`` to the expected locations."""
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    packages = payload.get("packages") if isinstance(payload, dict) else payload
    if not isinstance(packages, list):
        raise ValueError("locator answer key must contain a packages list")
    found: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in packages:
        if not isinstance(item, dict):
            continue
        name = str(item.get("package_name") or "").strip()
        version = str(item.get("package_version") or "").strip()
        if not name or not version:
            continue
        locations = item.get("locations") if isinstance(item.get("locations"), list) else []
        found[(name, version)] = [entry for entry in locations if isinstance(entry, dict)]
    return found


def predicted_locations(state: dict) -> list[dict[str, Any]]:
    """Locations the locator returned, falling back to file names."""
    items = []
    for item in state.get("debug_locations") or []:
        if not isinstance(item, dict):
            continue
        items.append({
            "path": item.get("path") or "",
            "function": item.get("function") or "",
            "line": item.get("line"),
        })
    if items:
        return items
    return [
        {"path": path, "function": "", "line": None}
        for path in (state.get("localized_files") or [])
        if path
    ]


def located_file_ratio(state: dict, expected: list[dict[str, Any]]) -> str | None:
    """Return ``located/total`` for the expected files, or ``None`` when unscored."""
    files = _expected_files(expected)
    if not files:
        return None
    predicted = _predicted_paths(state)
    hit = sum(1 for path in files if any(_same_path(item, path) for item in predicted))
    return f"{hit}/{len(files)}"


def _expected_files(expected: list[dict[str, Any]]) -> list[str]:
    files = []
    seen = set()
    for item in expected:
        path = str(item.get("path") or "").replace("\\", "/").strip()
        key = path.casefold()
        if not path or key in seen:
            continue
        seen.add(key)
        files.append(path)
    return files


def _predicted_paths(state: dict) -> list[str]:
    paths = []
    for key in ("located_entities", "debug_locations"):
        for item in state.get(key) or []:
            if isinstance(item, dict) and item.get("path"):
                paths.append(str(item.get("path") or ""))
    if paths:
        return paths
    return [str(path) for path in (state.get("localized_files") or []) if path]


def match_locations(predicted: list[dict[str, Any]], expected: list[dict[str, Any]]) -> bool | None:
    """Return whether every expected location was found. ``None`` means unscored."""
    if not expected:
        return None
    return all(_hit(predicted, item) for item in expected)


def _hit(predicted: list[dict[str, Any]], expected: dict[str, Any]) -> bool:
    path = str(expected.get("path") or "")
    function = str(expected.get("function") or "")
    line_set = _line_set(expected.get("lines"))
    if not path:
        return False
    for item in predicted:
        if not _same_path(str(item.get("path") or ""), path):
            continue
        function_ok = _same_function(str(item.get("function") or ""), function) if function else False
        line_ok = _line_hit(item.get("line"), line_set)
        if function and line_set:
            if function_ok or line_ok:
                return True
        elif function:
            if function_ok:
                return True
        elif line_set:
            if line_ok:
                return True
        else:
            return True
    return False


def _line_set(raw: Any) -> set[int]:
    if not isinstance(raw, list):
        return set()
    lines = set()
    for item in raw:
        try:
            lines.add(int(item))
        except (TypeError, ValueError):
            continue
    return lines


def _line_hit(raw: Any, expected: set[int]) -> bool:
    if not expected:
        return False
    try:
        return int(raw) in expected
    except (TypeError, ValueError):
        return False


def _same_path(predicted: str, expected: str) -> bool:
    left = predicted.replace("\\", "/").strip().casefold()
    right = expected.replace("\\", "/").strip().casefold()
    if not left or not right:
        return False
    return left == right or left.endswith("/" + right) or right.endswith("/" + left)


def _same_function(predicted: str, expected: str) -> bool:
    left = predicted.strip().casefold()
    right = expected.strip().casefold()
    if not left or not right:
        return False
    return left == right or left.endswith("." + right) or right.endswith("." + left)
