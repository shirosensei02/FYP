"""Disk catalog of function and class names, plus body lookup for the debugger.

The catalog file stores paths and names only. Advisory marks are added when the
prompt is built and are not written back. Lookup reads bodies from source.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from vulnerability_localization import extract_focus_terms

logger = logging.getLogger(__name__)

INDEX_ROOT = Path(__file__).resolve().parent / "package_index"
SOURCE_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx", ".cts", ".mts")
MAX_LOOKUP_FUNCTIONS = 3
MAX_LOOKUP_BODY_CHARS = 12_000
MAX_BODY_LOADS = 8
_SKIP_METHODS = {
    "if", "for", "while", "switch", "catch", "function", "return", "do", "else",
}

_FUNCTION_RE = re.compile(
    r"^[ \t]*(?P<export>export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\(",
    re.MULTILINE,
)
_CLASS_RE = re.compile(
    r"^[ \t]*(?P<export>export\s+)?class\s+(?P<name>[A-Za-z_$][\w$]*)\b",
    re.MULTILINE,
)
_CONST_RE = re.compile(
    r"^[ \t]*(?P<export>export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:async\s+)?(?:function\b|(?:\([^)\n]*\)|[A-Za-z_$][\w$]*)\s*=>)",
    re.MULTILINE,
)
_EXPORT_ASSIGN_RE = re.compile(
    r"^[ \t]*(?:module\.)?exports\.(?P<name>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:async\s+)?(?:function\b|(?:\([^)\n]*\)|[A-Za-z_$][\w$]*)\s*=>)",
    re.MULTILINE,
)
_METHOD_RE = re.compile(
    r"^[ \t]*(?:async\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*\([^)\n]*\)\s*\{",
    re.MULTILINE,
)
_EXPORT_NAME_RE = re.compile(
    r"(?:module\.)?exports\.(?P<name>[A-Za-z_$][\w$]*)\s*="
)


@dataclass(frozen=True)
class Symbol:
    path: str
    name: str
    exported: bool
    start: int
    end: int

    @property
    def key(self) -> str:
        return f"{self.path}:{self.name}"


def index_node(state: dict) -> dict:
    """Build the catalog once, then apply a pending lookup or drop."""
    source_dir = state.get("source_dir")
    if not source_dir or not Path(source_dir).is_dir():
        return _terminal(state, "cannot_locate", "missing source_dir")

    source_path = Path(source_dir)
    symbols = ensure_index(
        source_path,
        state.get("package_name") or "package",
        state.get("package_version") or "unknown",
    )
    findings = state.get("current_vulnerabilities") or state.get("vulnerabilities") or []
    catalog = render_catalog(symbols, extract_focus_terms(findings))
    if not symbols:
        return _terminal(state, "cannot_locate", catalog)

    in_prompt = [dict(item) for item in state.get("debug_in_prompt") or []]
    retrieved = [dict(item) for item in state.get("debug_retrieved") or []]
    body_loads = int(state.get("debug_body_loads") or 0)
    status = state.get("debug_status") or "running"
    request = state.get("debug_request") or None
    if request and status == "running":
        applied = apply_lookup(
            source_path,
            symbols,
            request=list(request.get("request") or []),
            drop=list(request.get("drop") or []),
            in_prompt=in_prompt,
            retrieved=retrieved,
            body_loads=body_loads,
        )
        in_prompt = applied["debug_in_prompt"]
        retrieved = applied["debug_retrieved"]
        body_loads = applied["debug_body_loads"]
        if body_loads >= MAX_BODY_LOADS:
            status = "capped"

    return {
        "symbol_catalog": catalog,
        "debug_in_prompt": in_prompt,
        "debug_retrieved": retrieved,
        "debug_body_loads": body_loads,
        "debug_status": status,
        "debug_request": None,
        "debug_rounds": int(state.get("debug_rounds") or 0),
        "debug_actions": list(state.get("debug_actions") or []),
    }


def ensure_index(source_dir: Path, package_name: str, package_version: str) -> list[Symbol]:
    """Scan source and write the name catalog if this version has none yet."""
    symbols = scan_source(source_dir)
    path = catalog_path(package_name, package_version)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_disk_catalog(symbols), encoding="utf-8")
        logger.info("symbol_index: wrote %s (%d names)", path, len(symbols))
    return symbols


def scan_source(source_dir: Path) -> list[Symbol]:
    symbols: list[Symbol] = []
    for path in _source_files(source_dir):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        relative = path.relative_to(source_dir).as_posix()
        symbols.extend(_scan_text(relative, text))
    return symbols


def render_catalog(symbols: list[Symbol], advisory_terms: set[str]) -> str:
    """One line per file. Advisory matches are marked for the prompt only."""
    grouped: dict[str, list[Symbol]] = {}
    for symbol in symbols:
        grouped.setdefault(symbol.path, []).append(symbol)
    lines = []
    for path, items in grouped.items():
        rendered = []
        for symbol in sorted(items, key=lambda item: _prompt_order(item, advisory_terms)):
            label = symbol.name
            if symbol.name.lower() in advisory_terms:
                label += " [advisory]"
            if symbol.exported:
                label += " [export]"
            rendered.append(label)
        lines.append(f"{path}: {', '.join(rendered)}")
    return "\n".join(lines)


def render_disk_catalog(symbols: list[Symbol]) -> str:
    grouped: dict[str, list[Symbol]] = {}
    for symbol in symbols:
        grouped.setdefault(symbol.path, []).append(symbol)
    lines = []
    for path, items in grouped.items():
        names = [f"{item.name} [export]" if item.exported else item.name for item in items]
        lines.append(f"{path}: {', '.join(names)}")
    text = "\n".join(lines)
    return f"{text}\n" if text else ""


def apply_lookup(
    source_dir: Path,
    symbols: list[Symbol],
    *,
    request: list[str],
    drop: list[str],
    in_prompt: list[dict],
    retrieved: list[dict],
    body_loads: int,
) -> dict:
    """Drop named bodies, then add up to three requested bodies."""
    drop_keys = _resolve_keys(symbols, drop)
    kept = [item for item in in_prompt if item.get("key") not in drop_keys]
    for item in retrieved:
        if item.get("key") in drop_keys and item.get("status") == "in_prompt":
            item["status"] = "dropped"

    loads = body_loads
    added_chars = 0
    added = 0
    for token in request:
        if added >= MAX_LOOKUP_FUNCTIONS or loads >= MAX_BODY_LOADS:
            break
        matches = _resolve_symbols(symbols, token)
        if not matches:
            _mark_retrieved(retrieved, token, token, "not_found")
            continue
        for symbol in matches:
            if added >= MAX_LOOKUP_FUNCTIONS or loads >= MAX_BODY_LOADS:
                break
            if any(item.get("key") == symbol.key for item in kept):
                _mark_retrieved(retrieved, symbol.key, symbol.key, "in_prompt")
                continue
            body = _read_body(source_dir, symbol)
            room = MAX_LOOKUP_BODY_CHARS - added_chars
            if room < 200:
                break
            if len(body) > room:
                body = body[:room] + "\n/* truncated */\n"
            kept.append({
                "key": symbol.key,
                "path": symbol.path,
                "name": symbol.name,
                "body": body,
            })
            _mark_retrieved(retrieved, symbol.key, symbol.key, "in_prompt")
            added_chars += len(body)
            added += 1
            loads += 1
    return {
        "debug_in_prompt": kept,
        "debug_retrieved": retrieved,
        "debug_body_loads": loads,
    }


def lookup_bodies(source_dir: Path, symbols: list[Symbol], names: list[str]) -> list[dict]:
    """Read bodies for a final handoff. This does not change the catalog."""
    found = []
    for token in names:
        for symbol in _resolve_symbols(symbols, token):
            found.append({
                "path": symbol.path,
                "function": symbol.name,
                "body": _read_body(source_dir, symbol),
            })
    return found


def catalog_path(package_name: str, package_version: str) -> Path:
    return INDEX_ROOT / _segment(package_name) / _segment(package_version) / "symbols.txt"


def _terminal(state: dict, status: str, catalog: str) -> dict:
    logger.info("symbol_index: %s", status)
    return {
        "symbol_catalog": catalog,
        "debug_status": status,
        "debug_request": None,
        "debug_locations": list(state.get("debug_locations") or []),
        "debug_in_prompt": list(state.get("debug_in_prompt") or []),
        "debug_retrieved": list(state.get("debug_retrieved") or []),
        "debug_rounds": int(state.get("debug_rounds") or 0),
        "debug_body_loads": int(state.get("debug_body_loads") or 0),
        "debug_actions": list(state.get("debug_actions") or []),
    }


def _source_files(source_dir: Path) -> list[Path]:
    files = []
    for path in sorted(source_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if path.name.endswith(".d.ts"):
            continue
        if "node_modules" in path.relative_to(source_dir).parts:
            continue
        files.append(path)
    return files


def _scan_text(relative: str, text: str) -> list[Symbol]:
    found: dict[str, Symbol] = {}
    exported = {match.group("name") for match in _EXPORT_NAME_RE.finditer(text)}

    def add(name: str, start: int, is_export: bool) -> None:
        if name in found:
            if is_export:
                current = found[name]
                found[name] = Symbol(relative, name, True, current.start, current.end)
            return
        end = _statement_end(text, start)
        found[name] = Symbol(relative, name, is_export or name in exported, start, end)

    for pattern, assigned_export in (
        (_FUNCTION_RE, False),
        (_CLASS_RE, False),
        (_CONST_RE, False),
        (_EXPORT_ASSIGN_RE, True),
    ):
        for match in pattern.finditer(text):
            is_export = assigned_export or bool(match.groupdict().get("export"))
            add(match.group("name"), match.start(), is_export)
    for match in _METHOD_RE.finditer(text):
        name = match.group("name")
        if name not in _SKIP_METHODS:
            add(name, match.start(), False)
    return list(found.values())


def _statement_end(text: str, start: int) -> int:
    brace = _find_body_brace(text, start)
    if brace is None:
        line_end = text.find("\n", start)
        return len(text) if line_end == -1 else line_end + 1
    return _closing_brace(text, brace) + 1


def _find_body_brace(text: str, start: int) -> int | None:
    limit = min(len(text), start + 400)
    arrow = text.find("=>", start, limit)
    brace = text.find("{", start, limit if arrow == -1 else len(text))
    if brace == -1:
        return None
    if arrow != -1 and arrow < brace:
        line_end = text.find("\n", arrow)
        if line_end != -1 and brace > line_end and text.find("{", arrow, line_end) == -1:
            return None
    return brace


def _closing_brace(text: str, brace: int) -> int:
    depth = 0
    quote = ""
    index = brace
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return len(text) - 1


def _read_body(source_dir: Path, symbol: Symbol) -> str:
    text = (source_dir / symbol.path).read_text(encoding="utf-8")
    return text[symbol.start:symbol.end]


def _resolve_symbols(symbols: list[Symbol], token: str) -> list[Symbol]:
    token = token.strip().replace("\\", "/")
    if ":" in token:
        path, name = token.rsplit(":", 1)
        return [symbol for symbol in symbols if symbol.path == path and symbol.name == name]
    return [symbol for symbol in symbols if symbol.name == token]


def _resolve_keys(symbols: list[Symbol], tokens: list[str]) -> set[str]:
    keys: set[str] = set()
    for token in tokens:
        matches = _resolve_symbols(symbols, token)
        if matches:
            keys.update(symbol.key for symbol in matches)
        else:
            keys.add(token.strip())
    return keys


def _mark_retrieved(retrieved: list[dict], key: str, label: str, status: str) -> None:
    for item in retrieved:
        if item.get("key") == key:
            item["status"] = status
            item["label"] = label
            return
    retrieved.append({"key": key, "label": label, "status": status})


def _prompt_order(symbol: Symbol, advisory_terms: set[str]) -> tuple:
    advisory = 0 if symbol.name.lower() in advisory_terms else 1
    exported = 0 if symbol.exported else 1
    return (advisory, exported, symbol.name)


def _segment(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip(".")[:80] or "unknown"
    return f"{slug}-{hashlib.sha256(value.encode()).hexdigest()[:10]}"
