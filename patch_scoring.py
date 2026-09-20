"""
LangGraph node: score the generated patch against the official answer key.

Compares maintainer vs LLM patch on:
  location     — same | overlapping | different  (hunk/file overlap)
  strategy     — same | similar | different      (heuristic fix family)
  completeness — full | partial | none           (vendor hunk coverage + rescan)

Scoring does not change pass/fail and must not feed back into generation.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from state import GraphState, PatchScore

_DIFF_PATH_RE = re.compile(r"^(?:---|\+\+\+) [ab]/(.+)$", re.MULTILINE)
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_MANIFEST_NAMES = {"package.json", "package-lock.json", "npm-shrinkwrap.json"}
_DOC_NAMES = {"readme.md", "changelog.md", "license", "license.md"}
_HUNK_SLACK = 5

LocationLabel = Literal["same", "overlapping", "different", "skipped"]
StrategyLabel = Literal["same", "similar", "different", "skipped"]
CompletenessLabel = Literal["full", "partial", "none", "skipped"]

_STRATEGY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "sanitization": (
        "sanitize",
        "escape",
        "encodeuricomponent",
        "encodeuri(",
        "dompurify",
        "xss",
        "htmlspecialchars",
        "he.encode",
        "he.escape",
    ),
    "prototype_guard": (
        "__proto__",
        ".prototype",
        "constructor",
        "object.create(null)",
        "hasownproperty",
        "object.freeze",
        "object.hasown",
    ),
    "validation": (
        "typeof ",
        "instanceof ",
        "array.isarray",
        "number.isfinite",
        "number.isinteger",
        "allowlist",
        "whitelist",
        "denylist",
        "blacklist",
    ),
    "authz": (
        "authorize",
        "isadmin",
        "csrf",
        "forbidden",
        "permission",
        "unauthenticated",
        "isauthenticated",
    ),
}

_SIMILAR_STRATEGIES = {
    frozenset({"sanitization", "validation"}),
    frozenset({"sanitization", "harden"}),
    frozenset({"validation", "harden"}),
    frozenset({"prototype_guard", "validation"}),
    frozenset({"prototype_guard", "harden"}),
    frozenset({"prototype_guard", "sanitization"}),
}

_LABEL_SCORE = {"same": 1.0, "similar": 0.5, "different": 0.0}
_COMPLETENESS_SCORE = {"full": 1.0, "partial": 0.5, "none": 0.0}


@dataclass(frozen=True)
class Hunk:
    path: str
    start: int
    count: int


def _normalize_path(path: str) -> str:
    return path.strip().replace("\\", "/").lstrip("./").split("\t")[0]


def _basename(path: str) -> str:
    return Path(_normalize_path(path)).name.lower()


def _paths_equivalent(left: str, right: str) -> bool:
    return _normalize_path(left).lower() == _normalize_path(right).lower() or _basename(left) == _basename(right)


def _paths_from_unified_diff(diff: str) -> list[str]:
    paths: list[str] = []
    seen = set()
    for match in _DIFF_PATH_RE.finditer(diff):
        path = _normalize_path(match.group(1))
        if path in {"dev/null", ""} or path.lower() in seen:
            continue
        seen.add(path.lower())
        paths.append(path)
    return paths


def _parse_hunks(diff: str) -> list[Hunk]:
    hunks: list[Hunk] = []
    current_path: str | None = None
    for line in diff.splitlines():
        if line.startswith("--- ") or line.startswith("+++ "):
            raw = line[4:].strip()
            if raw.startswith("a/") or raw.startswith("b/"):
                raw = raw[2:]
            path = _normalize_path(raw)
            if path not in {"/dev/null", "dev/null", ""}:
                current_path = path
            continue
        match = _HUNK_RE.match(line)
        if match and current_path:
            start = int(match.group(1))
            count = int(match.group(2) or "1")
            hunks.append(Hunk(current_path, start, max(count, 1)))
    return hunks


def _hunks_overlap(vendor: Hunk, generated: Hunk, slack: int = _HUNK_SLACK) -> bool:
    if not _paths_equivalent(vendor.path, generated.path):
        return False
    vendor_end = vendor.start + vendor.count + slack
    generated_end = generated.start + generated.count
    return (vendor.start - slack) < generated_end and generated.start < vendor_end


def _added_text(diff: str) -> str:
    lines = [
        line[1:]
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    return "\n".join(lines).lower()


def _is_non_code_file(path: str) -> bool:
    name = _basename(path)
    return name in _MANIFEST_NAMES or name in _DOC_NAMES


def _classify_strategy(diff: str, files: list[str]) -> str | None:
    if not diff.strip() and not files:
        return None
    code_files = [path for path in files if not _is_non_code_file(path)]
    added = _added_text(diff)
    if files and not code_files:
        return "version_bump"

    scores = {
        label: sum(1 for keyword in keywords if keyword in added)
        for label, keywords in _STRATEGY_KEYWORDS.items()
    }
    if "===" in added or "!==" in added:
        scores["harden"] = scores.get("harden", 0) + 1
    best = max(scores, key=scores.get) if scores else None
    if best and scores[best] > 0:
        return best
    if files and not code_files:
        return "version_bump"
    if not added and not files:
        return None
    return "other"


def _compare_strategy(generated: str | None, vendor: str | None) -> StrategyLabel:
    if not generated or not vendor:
        return "skipped"
    if generated == vendor:
        return "same"
    if generated == "other" or vendor == "other":
        return "different"
    if frozenset({generated, vendor}) in _SIMILAR_STRATEGIES:
        return "similar"
    return "different"


def _match_files(generated: list[str], vendor: list[str]) -> tuple[list[str], list[str], list[str]]:
    matched: list[str] = []
    used_generated: set[int] = set()
    for vendor_path in vendor:
        for index, generated_path in enumerate(generated):
            if index in used_generated:
                continue
            if _paths_equivalent(vendor_path, generated_path):
                matched.append(vendor_path.lower())
                used_generated.add(index)
                break
    missing = [path.lower() for path in vendor if path.lower() not in matched]
    extra = [
        path.lower()
        for index, path in enumerate(generated)
        if index not in used_generated
    ]
    return sorted(set(matched)), sorted(set(missing)), sorted(set(extra))


def _file_jaccard(matched: list[str], missing: list[str], extra: list[str]) -> float:
    union = len(matched) + len(missing) + len(extra)
    return round(len(matched) / union, 4) if union else 0.0


def _location_label(overlap: float | None, matched_files: list[str]) -> LocationLabel:
    if overlap is None and not matched_files:
        return "skipped"
    if overlap is not None and overlap >= 0.8:
        return "same"
    if (overlap is not None and overlap > 0) or matched_files:
        return "overlapping"
    return "different"


def _completeness_label(
    vendor_coverage: float | None,
    scan_clean: bool | None,
    matched_files: list[str],
    remaining: list[Any] | None,
) -> CompletenessLabel:
    if scan_clean:
        return "full"
    if vendor_coverage is not None and vendor_coverage >= 0.8:
        return "full"
    if (vendor_coverage is not None and vendor_coverage > 0) or matched_files:
        return "partial"
    if scan_clean is False or remaining:
        return "none"
    if vendor_coverage is None and scan_clean is None:
        return "skipped"
    return "none"


def _materialize_generated_diff(state: GraphState) -> tuple[str, list[str]]:
    patch = state.get("current_patch") or {}
    declared = [_normalize_path(path) for path in patch.get("target_files") or [] if path]
    diff = patch.get("diff") or ""
    if not isinstance(diff, str) or not diff.strip():
        return "", declared

    try:
        file_map = json.loads(diff)
    except json.JSONDecodeError:
        file_map = None

    if isinstance(file_map, dict):
        mapped = [_normalize_path(str(path)) for path in file_map if path]
        source_dir = state.get("source_dir")
        parts: list[str] = []
        for rel_path, content in file_map.items():
            rel = _normalize_path(str(rel_path))
            original = ""
            if source_dir:
                candidate = Path(source_dir) / rel
                if candidate.is_file():
                    original = candidate.read_text(encoding="utf-8", errors="ignore")
            parts.append(
                "".join(
                    difflib.unified_diff(
                        original.splitlines(keepends=True),
                        str(content).splitlines(keepends=True),
                        fromfile=f"a/{rel}",
                        tofile=f"b/{rel}",
                    )
                )
            )
        return "".join(parts), mapped or declared

    return diff, _paths_from_unified_diff(diff) or declared


def patch_scoring(state: GraphState) -> dict[str, Any]:
    answer_key = state.get("answer_key") or {}
    vendor_diff = answer_key.get("diff") or ""
    vendor_files = [_normalize_path(path) for path in answer_key.get("files") or [] if path]
    if not vendor_files:
        vendor_files = _paths_from_unified_diff(vendor_diff)

    generated_diff, generated_files = _materialize_generated_diff(state)
    if not generated_files:
        generated_files = _paths_from_unified_diff(generated_diff)

    matched_files, missing_files, extra_files = _match_files(generated_files, vendor_files)
    file_jaccard = _file_jaccard(matched_files, missing_files, extra_files) if vendor_files else None

    vendor_hunks = _parse_hunks(vendor_diff) if vendor_diff else []
    generated_hunks = _parse_hunks(generated_diff) if generated_diff else []
    matched_hunks = 0
    hunk_coverage: float | None = None
    if vendor_hunks:
        matched_hunks = sum(
            1
            for vendor_hunk in vendor_hunks
            if any(_hunks_overlap(vendor_hunk, generated_hunk) for generated_hunk in generated_hunks)
        )
        hunk_coverage = round(matched_hunks / len(vendor_hunks), 4)

    if hunk_coverage is not None:
        location_overlap = hunk_coverage
    else:
        location_overlap = file_jaccard

    location = _location_label(location_overlap, matched_files)

    vendor_strategy = _classify_strategy(vendor_diff, vendor_files)
    if vendor_strategy is None and answer_key.get("status") == "version_only":
        vendor_strategy = "version_bump"
    generated_strategy = _classify_strategy(generated_diff, generated_files)
    strategy = _compare_strategy(generated_strategy, vendor_strategy)

    validation = state.get("validation")
    scan_clean: bool | None
    if isinstance(validation, dict) and "revalidation_scan_clean" in validation:
        scan_clean = bool(validation.get("revalidation_scan_clean"))
    else:
        scan_clean = None
    remaining = state.get("remaining_vulnerabilities")
    completeness = _completeness_label(hunk_coverage, scan_clean, matched_files, remaining)

    any_metric = any(label != "skipped" for label in (location, strategy, completeness))
    score: PatchScore = {
        "status": "scored" if any_metric else "skipped",
        "location": location,
        "location_overlap": location_overlap,
        "location_file_jaccard": file_jaccard,
        "location_score": location_overlap,
        "generated_files": generated_files,
        "vendor_files": vendor_files,
        "matched_files": matched_files,
        "missing_files": missing_files,
        "extra_files": extra_files,
        "matched_hunks": matched_hunks,
        "vendor_hunks": len(vendor_hunks),
        "strategy": strategy,
        "strategy_generated": generated_strategy,
        "strategy_vendor": vendor_strategy,
        "strategy_score": _LABEL_SCORE.get(strategy),
        "completeness": completeness,
        "completeness_score": _COMPLETENESS_SCORE.get(completeness),
        "completeness_vendor_coverage": hunk_coverage,
    }
    mongo_id = state.get("mongo_id")
    if mongo_id:
        _persist_score(mongo_id, score, answer_key)

    return {"patch_score": score}


def _persist_score(mongo_id: str, score: PatchScore, answer_key: dict) -> None:
    from db import update_patch_score

    update_patch_score(mongo_id, score, answer_key=answer_key)
