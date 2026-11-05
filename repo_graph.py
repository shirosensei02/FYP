"""Package graph and the three localization tools.

The graph is built once per package version. Nodes are directories, files,
classes, and functions. Edges are contain, import, invoke, and inherit.
An entity index maps ids and names across the whole package, then BM25.
SearchEntity, TraverseGraph, and RetrieveEntity read that graph. The node
builds it, runs one pending tool request, and records which node asked.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from collections import defaultdict
from pathlib import Path

from js_ast import JsFile, parse_javascript
from symbol_index import SOURCE_SUFFIXES, _scan_text

logger = logging.getLogger(__name__)

INDEX_ROOT = Path(__file__).resolve().parent / "repo_index"
TOOLS = {"SearchEntity", "TraverseGraph", "RetrieveEntity"}
ENTITY_TYPES = {"directory", "file", "class", "function"}
RELATION_TYPES = {"contain", "import", "invoke", "inherit"}
MAX_HOPS = 3
MAX_SEARCH_HITS = 8
MAX_SNIPPET_CHARS = 800
MAX_CODE_CHARS = 8_000
_CACHE: dict[str, dict] = {}
_CALL_RE = re.compile(r"(?<!function\s)\b([A-Za-z_$][\w$]*)\s*\(")
_EXTENDS_RE = re.compile(
    r"\bclass\s+([A-Za-z_$][\w$]*)\s+extends\s+([A-Za-z_$][\w$]*)"
)
_IMPORT_RE = re.compile(
    r"(?:require\(\s*|from\s+|import\s*)[\"'](\.[^\"']+)[\"']"
)
_SKIP_CALLS = {
    "if", "for", "while", "switch", "catch", "function", "return", "do", "else",
    "require", "import", "super", "new", "typeof", "await", "async",
}


def route_after_repo_graph(state: dict) -> str:
    """Send a tool result back to the node that requested it."""
    if state.get("graph_return") == "patch_generation":
        return "generation"
    return "locator"


def repo_graph_node(state: dict) -> dict:
    """Build the graph once, or run the pending Search, Traverse, or Retrieve."""
    source_dir = state.get("source_dir")
    request = state.get("graph_request") if isinstance(state.get("graph_request"), dict) else None
    caller = str((request or {}).get("caller") or "locator")
    if caller not in {"locator", "patch_generation"}:
        caller = "locator"
    if not source_dir or not Path(source_dir).is_dir():
        return {
            "repo_graph_ready": False,
            "repo_graph_summary": "missing source_dir",
            "graph_request": None,
            "graph_result": {"error": "missing source_dir"},
            "graph_return": caller if request else "locator",
        }

    graph = ensure_repo_graph(
        Path(source_dir),
        state.get("package_name") or "package",
        state.get("package_version") or "unknown",
    )
    summary = f"{len(graph['nodes'])} nodes, {len(graph['edges'])} edges"
    if not request:
        return {
            "repo_graph_ready": True,
            "repo_graph_summary": summary,
            "graph_request": None,
            "graph_result": None,
            "graph_return": "locator",
        }
    return {
        "repo_graph_ready": True,
        "repo_graph_summary": summary,
        "graph_request": None,
        "graph_result": run_tool(graph, request),
        "graph_return": caller,
    }


def ensure_repo_graph(source_dir: Path, package_name: str, package_version: str) -> dict:
    """Load the on-disk graph, building it the first time this version is seen."""
    key = str(source_dir.resolve())
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    path = graph_path(package_name, package_version)
    if path.is_file():
        graph = json.loads(path.read_text(encoding="utf-8"))
    else:
        graph = build_graph(source_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"nodes": graph["nodes"], "edges": graph["edges"]}), encoding="utf-8")
        logger.info("repo_graph: wrote %s (%d nodes)", path, len(graph["nodes"]))
    graph["source_dir"] = str(source_dir.resolve())
    attach_entity_index(graph)
    _CACHE[key] = graph
    return graph


def graph_path(package_name: str, package_version: str) -> Path:
    return INDEX_ROOT / _segment(package_name) / _segment(package_version) / "graph.json"


def build_graph(source_dir: Path) -> dict:
    """Parse the package into nodes and contain, import, invoke, and inherit edges."""
    nodes: dict[str, dict] = {}
    edges: list[dict[str, str]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    files = _source_files(source_dir)
    texts: dict[str, str] = {}
    ast_files: dict[str, JsFile] = {}
    regex_files: dict[str, list] = {}
    for path in files:
        relative = path.relative_to(source_dir).as_posix()
        try:
            texts[relative] = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        _add_file_nodes(nodes, edges, seen_edges, relative)
        facts = parse_javascript(relative, texts[relative])
        if facts is None:
            regex_files[relative] = _scan_text(relative, texts[relative])
        else:
            ast_files[relative] = facts

    name_index: dict[str, list[str]] = {}
    for relative, facts in ast_files.items():
        for symbol in facts.symbols:
            entity_id = f"{relative}:{symbol.qualified}"
            nodes[entity_id] = {
                "id": entity_id,
                "type": symbol.kind,
                "name": symbol.name,
                "qualified": symbol.qualified,
                "path": relative,
                "start": symbol.start,
                "end": symbol.end,
                "exports": list(symbol.export_names),
            }
            name_index.setdefault(symbol.name, []).append(entity_id)
            parent_name = symbol.qualified.rsplit(".", 1)[0] if "." in symbol.qualified else ""
            parent = f"{relative}:{parent_name}" if parent_name and f"{relative}:{parent_name}" in nodes else relative
            _add_edge(edges, seen_edges, parent, entity_id, "contain")
    for relative, file_symbols in regex_files.items():
        classes = [symbol for symbol in file_symbols if _is_class(texts[relative], symbol.start)]
        for symbol in file_symbols:
            parent = _enclosing_class(symbol, classes)
            kind = "class" if symbol in classes else "function"
            qualified = f"{parent.name}.{symbol.name}" if parent and kind == "function" else symbol.name
            entity_id = f"{relative}:{qualified}"
            nodes[entity_id] = {
                "id": entity_id,
                "type": kind,
                "name": symbol.name,
                "qualified": qualified,
                "path": relative,
                "start": symbol.start,
                "end": symbol.end,
                "exports": [symbol.name],
            }
            name_index.setdefault(symbol.name, []).append(entity_id)
            owner = f"{relative}:{parent.name}" if parent and kind == "function" else relative
            _add_edge(edges, seen_edges, owner, entity_id, "contain")

    _apply_ast_relations(ast_files, nodes, edges, seen_edges)
    for relative, file_symbols in regex_files.items():
        _add_imports(nodes, edges, seen_edges, relative, texts[relative])
        _add_inherits(nodes, edges, seen_edges, relative, texts[relative], name_index)
        _add_invokes(nodes, edges, seen_edges, relative, texts[relative], file_symbols, name_index)

    graph = {
        "nodes": list(nodes.values()),
        "edges": edges,
        "source_dir": str(source_dir.resolve()),
    }
    attach_entity_index(graph)
    return graph


def run_tool(graph: dict, request: dict) -> dict:
    """Run one tool. Unknown tools return an error the caller can read."""
    tool = str(request.get("tool") or "")
    arguments = request.get("arguments") if isinstance(request.get("arguments"), dict) else {}
    if tool == "SearchEntity":
        return search_entity(graph, _as_list(arguments.get("keywords")), arguments.get("detail") or "preview")
    if tool == "TraverseGraph":
        return traverse_graph(
            graph,
            _as_list(arguments.get("start_ids")),
            str(arguments.get("direction") or "out"),
            _as_int(arguments.get("hops"), 1),
            _as_list(arguments.get("entity_types")),
            _as_list(arguments.get("relation_types")),
        )
    if tool == "RetrieveEntity":
        return retrieve_entity(graph, _as_list(arguments.get("entity_ids")))
    return {"tool": tool, "error": "unknown tool", "entities": []}


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def attach_entity_index(graph: dict) -> dict:
    """Build the id, name, and BM25 indexes once. Call edges stay on the graph."""
    if isinstance(graph.get("index"), EntityIndex):
        return graph
    graph["index"] = EntityIndex(graph)
    return graph


class EntityIndex:
    """Lookup order is exact id, global name, BM25 over ids, then BM25 over bodies.

    The name dictionary is global. A function in one directory and its caller in
    another share a name key, and the invoke or inherit edge is what makes them
    neighbors.
    """

    def __init__(self, graph: dict):
        self.graph = graph
        self.nodes = graph["nodes"]
        self.by_id = {node["id"]: node for node in self.nodes}
        self.names: dict[str, list[str]] = defaultdict(list)
        self.names_lower: dict[str, list[str]] = defaultdict(list)
        for node in self.nodes:
            for key in _index_keys(node):
                self.names[key].append(node["id"])
                self.names_lower[key.lower()].append(node["id"])
        self.id_bm25 = _BM25([_tokenize(f"{node['id']} {node.get('qualified', '')}") for node in self.nodes])
        self.code_bm25 = _BM25([
            _tokenize(_node_text(graph, node) if node["type"] in {"class", "function"} else "")
            for node in self.nodes
        ])

    def lookup(self, term: str) -> list[str]:
        if term in self.by_id:
            return [term]
        found = self._by_name(term, prefix="")
        if found:
            return found
        if "." not in term:
            return []
        prefix, last = term.rsplit(".", 1)
        return self._by_name(last.strip(), prefix=prefix.strip())

    def _by_name(self, term: str, prefix: str) -> list[str]:
        ids = self.names.get(term) or self.names_lower.get(term.lower()) or []
        unique = list(dict.fromkeys(ids))
        if not prefix:
            return unique
        required = {part.lower() for part in re.split(r"[./:]", prefix) if part}
        return [
            entity_id for entity_id in unique
            if required <= {part.lower() for part in re.split(r"[./:]", entity_id) if part}
        ]

    def bm25(self, query: list[str], kind: str) -> list[str]:
        scorer = self.id_bm25 if kind == "id" else self.code_bm25
        scored = [
            (score, node) for score, node in zip(scorer.scores(query), self.nodes) if score > 0
        ]
        scored.sort(key=lambda item: item[0], reverse=True)
        return [node["id"] for _score, node in scored[:MAX_SEARCH_HITS]]


def search_entity(graph: dict, keywords, detail: str = "preview") -> dict:
    """Walk the entity index from the exact id down to the code BM25."""
    attach_entity_index(graph)
    index: EntityIndex = graph["index"]
    tokens = [str(keyword).strip() for keyword in keywords if str(keyword).strip()]
    found: list[dict] = []
    seen: set[str] = set()
    missed: list[str] = []

    def add(entity_id: str) -> None:
        node = index.by_id.get(entity_id)
        if node is None or entity_id in seen:
            return
        seen.add(entity_id)
        found.append(node)

    for keyword in tokens:
        hits = index.lookup(keyword)
        if hits:
            for entity_id in hits:
                add(entity_id)
        else:
            missed.append(keyword)
    if missed and len(found) < MAX_SEARCH_HITS:
        query = _tokenize(" ".join(missed))
        for entity_id in index.bm25(query, "id"):
            add(entity_id)
            if len(found) >= MAX_SEARCH_HITS:
                break
        if len(found) < MAX_SEARCH_HITS:
            for entity_id in index.bm25(query, "code"):
                add(entity_id)
                if len(found) >= MAX_SEARCH_HITS:
                    break
    detail = detail if isinstance(detail, str) and detail in {"fold", "preview", "full"} else "preview"
    if detail == "preview" and len(found) > 3:
        detail = "fold"
    return {
        "tool": "SearchEntity",
        "entities": [_present(graph, node, detail) for node in found[:MAX_SEARCH_HITS]],
    }


def _index_keys(node: dict) -> set[str]:
    keys = {node["id"], str(node.get("name") or ""), str(node.get("qualified") or "")}
    path = str(node.get("path") or "")
    if path:
        keys.add(Path(path).name)
        keys.add(Path(path).stem)
    return {key for key in keys if key and key not in {".", "dir:."}}


def traverse_graph(
    graph: dict,
    start_ids,
    direction: str = "out",
    hops: int = 1,
    entity_types=None,
    relation_types=None,
) -> dict:
    """Breadth-first walk from the start ids, bounded by hops and edge type."""
    by_id = {node["id"]: node for node in graph["nodes"]}
    allowed_entities = {item for item in (entity_types or []) if item in ENTITY_TYPES}
    allowed_relations = {item for item in (relation_types or []) if item in RELATION_TYPES}
    direction = direction if direction in {"out", "in", "both"} else "out"
    hops = max(1, min(int(hops or 1), MAX_HOPS))
    starts = [str(entity_id) for entity_id in start_ids if str(entity_id) in by_id]
    relations: list[dict[str, str]] = []
    seen_relations: set[tuple[str, str, str]] = set()
    reached = set(starts)
    frontier = set(starts)
    for _hop in range(hops):
        nxt: set[str] = set()
        for edge in graph["edges"]:
            if allowed_relations and edge["type"] not in allowed_relations:
                continue
            pairs = []
            if direction in {"out", "both"}:
                pairs.append((edge["source"], edge["target"]))
            if direction in {"in", "both"}:
                pairs.append((edge["target"], edge["source"]))
            for origin, dest in pairs:
                if origin not in frontier or dest not in by_id:
                    continue
                if allowed_entities and by_id[dest]["type"] not in allowed_entities:
                    continue
                key = (edge["source"], edge["target"], edge["type"])
                if key not in seen_relations:
                    seen_relations.add(key)
                    relations.append(edge)
                nxt.add(dest)
        frontier = nxt - reached
        reached.update(nxt)
        if not frontier:
            break
    entities = [_present(graph, by_id[entity_id], "fold") for entity_id in reached if entity_id in by_id]
    return {"tool": "TraverseGraph", "entities": entities, "relations": relations}


def retrieve_entity(graph: dict, entity_ids) -> dict:
    """Return the full source of the requested entities."""
    by_id = {node["id"]: node for node in graph["nodes"]}
    entities = []
    for raw in entity_ids:
        node = by_id.get(str(raw))
        if node is None:
            continue
        entities.append(_present(graph, node, "full"))
    return {"tool": "RetrieveEntity", "entities": entities}


def _present(graph: dict, node: dict, detail: str) -> dict:
    presented = {
        "id": node["id"],
        "type": node["type"],
        "name": node.get("name") or node["id"],
        "qualified": node.get("qualified") or node.get("name") or node["id"],
        "path": node.get("path") or "",
    }
    if detail == "fold":
        return presented
    text = _node_text(graph, node)
    if detail == "full":
        presented["code"] = text[:MAX_CODE_CHARS]
        return presented
    presented["snippet"] = text[:MAX_SNIPPET_CHARS]
    return presented


def _node_text(graph: dict, node: dict) -> str:
    if node.get("type") not in {"class", "function"}:
        return str(node.get("qualified") or node.get("name") or "")
    cached = node.get("text")
    if isinstance(cached, str):
        return cached
    source = graph.get("source_dir")
    if not source:
        return ""
    try:
        text = (Path(source) / node["path"]).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        node["text"] = ""
        return ""
    body = text[int(node.get("start") or 0):int(node.get("end") or 0)]
    node["text"] = body
    return body


def _add_file_nodes(nodes, edges, seen_edges, relative: str) -> None:
    parts = Path(relative).parts[:-1]
    parent = "dir:."
    nodes.setdefault(parent, {"id": parent, "type": "directory", "name": ".", "qualified": ".", "path": "", "text": ""})
    walked = []
    for part in parts:
        walked.append(part)
        directory = "dir:" + "/".join(walked)
        nodes.setdefault(directory, {
            "id": directory,
            "type": "directory",
            "name": part,
            "qualified": "/".join(walked),
            "path": "/".join(walked),
            "text": "",
        })
        _add_edge(edges, seen_edges, parent, directory, "contain")
        parent = directory
    nodes[relative] = {
        "id": relative,
        "type": "file",
        "name": Path(relative).name,
        "qualified": relative,
        "path": relative,
        "text": "",
    }
    _add_edge(edges, seen_edges, parent, relative, "contain")


def _apply_ast_relations(ast_files: dict[str, JsFile], nodes: dict, edges: list, seen_edges: set) -> None:
    """Bind import aliases to the target class or function, then record calls and extends."""
    for relative, facts in ast_files.items():
        bindings: dict[str, tuple[str, str]] = {}
        for binding in facts.bindings:
            target_file = _resolve_import(nodes, Path(relative).parent, binding.specifier)
            if not target_file:
                continue
            _add_edge(edges, seen_edges, relative, target_file, "import")
            if binding.imported == "*":
                if binding.local:
                    bindings[binding.local] = ("*", target_file)
                continue
            entity = _symbol_in_file(nodes, target_file, binding.imported)
            if binding.local and entity:
                bindings[binding.local] = ("named", entity)
                _add_edge(edges, seen_edges, relative, entity, "import")
        for extend in facts.extends:
            child = f"{relative}:{extend.child}"
            bound = bindings.get(extend.parent)
            parent = bound[1] if bound and bound[0] == "named" else _class_named(nodes, extend.parent)
            if child in nodes and parent:
                _add_edge(edges, seen_edges, child, parent, "inherit")
        for call in facts.calls:
            target = _resolve_ast_call(call, bindings, nodes, relative)
            if target:
                _add_edge(edges, seen_edges, f"{relative}:{call.owner}", target, "invoke")


def _resolve_ast_call(call, bindings: dict[str, tuple[str, str]], nodes: dict, relative: str) -> str | None:
    if call.object == "this":
        return _symbol_in_file(nodes, relative, call.name)
    if call.object:
        bound = bindings.get(call.object)
        if bound and bound[0] == "*":
            return _symbol_in_file(nodes, bound[1], call.name)
        if bound and bound[0] == "named":
            entity = nodes.get(bound[1]) or {}
            method = f"{entity.get('path')}:{entity.get('qualified')}.{call.name}"
            if method in nodes:
                return method
        return _symbol_in_file(nodes, relative, call.name) or _global_function(nodes, call.name)
    bound = bindings.get(call.name)
    if bound and bound[0] == "named":
        return bound[1]
    if bound and bound[0] == "*":
        return _symbol_in_file(nodes, bound[1], "default")
    return _symbol_in_file(nodes, relative, call.name) or _global_function(nodes, call.name)


def _symbol_in_file(nodes: dict, file: str, name: str) -> str | None:
    exact_name = []
    exact_export = []
    qualified = []
    for node in nodes.values():
        if node.get("path") != file or node.get("type") not in {"function", "class"}:
            continue
        if node.get("name") == name:
            exact_name.append(node["id"])
        elif name in (node.get("exports") or []):
            exact_export.append(node["id"])
        elif node.get("qualified") == name or str(node.get("qualified") or "").endswith("." + name):
            qualified.append(node["id"])
    found = exact_name or exact_export or qualified
    return found[0] if found else None


def _class_named(nodes: dict, name: str) -> str | None:
    matches = [
        node["id"] for node in nodes.values()
        if node.get("type") == "class" and node.get("name") == name
    ]
    return matches[0] if matches else None


def _global_function(nodes: dict, name: str) -> str | None:
    matches = [
        node["id"] for node in nodes.values()
        if node.get("type") == "function" and node.get("name") == name
    ]
    return matches[0] if matches else None


def _add_imports(nodes, edges, seen_edges, relative: str, text: str) -> None:
    source = Path(relative)
    for match in _IMPORT_RE.finditer(text):
        target = _resolve_import(nodes, source.parent, match.group(1))
        if target:
            _add_edge(edges, seen_edges, relative, target, "import")


def _add_inherits(nodes, edges, seen_edges, relative: str, text: str, name_index: dict[str, list[str]]) -> None:
    for match in _EXTENDS_RE.finditer(text):
        child = f"{relative}:{match.group(1)}"
        parents = [entity_id for entity_id in name_index.get(match.group(2), []) if nodes.get(entity_id, {}).get("type") == "class"]
        if child not in nodes or not parents:
            continue
        _add_edge(edges, seen_edges, child, parents[0], "inherit")


def _add_invokes(nodes, edges, seen_edges, relative: str, text: str, file_symbols, name_index) -> None:
    owners = [node_id for node_id, node in nodes.items() if node.get("path") == relative and node["type"] == "function"]
    for match in _CALL_RE.finditer(text):
        name = match.group(1)
        if name in _SKIP_CALLS or _is_definition(text, match.start(), file_symbols):
            continue
        targets = [entity_id for entity_id in name_index.get(name, []) if nodes.get(entity_id, {}).get("type") == "function"]
        if not targets:
            continue
        same_file = [entity_id for entity_id in targets if entity_id.startswith(relative + ":")]
        target = same_file[0] if same_file else targets[0]
        for owner in owners:
            node = nodes[owner]
            if node.get("start") is None:
                continue
            if node["start"] <= match.start() < node.get("end", match.start()):
                if node.get("name") != name:
                    _add_edge(edges, seen_edges, owner, target, "invoke")
                break


def _is_definition(text: str, index: int, file_symbols) -> bool:
    for symbol in file_symbols:
        if not symbol.start <= index < symbol.start + 160:
            continue
        between = text[symbol.start:index]
        if between.strip() in {"", "async", "export", "export async", "static"}:
            return True
    return False


def _resolve_import(nodes: dict, parent: Path, specifier: str) -> str | None:
    base = (parent / specifier).as_posix()
    candidates = [base, *[f"{base}{suffix}" for suffix in SOURCE_SUFFIXES], *[f"{base}/index{suffix}" for suffix in SOURCE_SUFFIXES]]
    for candidate in candidates:
        if candidate in nodes and nodes[candidate]["type"] == "file":
            return candidate
    return None


def _enclosing_class(symbol, classes):
    found = None
    for owner in classes:
        if owner.name == symbol.name:
            continue
        if owner.start <= symbol.start < owner.end:
            found = owner
    return found


def _is_class(text: str, start: int) -> bool:
    window = text[start:start + 80]
    return bool(re.match(r"\s*(?:export\s+)?class\s+", window))


def _add_edge(edges, seen, source: str, target: str, kind: str) -> None:
    key = (source, target, kind)
    if source == target or key in seen:
        return
    seen.add(key)
    edges.append({"source": source, "target": target, "type": kind})


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


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text.lower())


class _BM25:
    def __init__(self, documents: list[list[str]]):
        self.docs = documents
        self.n = len(documents)
        self.k1 = 1.5
        self.b = 0.75
        self.avg = (sum(len(doc) for doc in documents) / self.n) if self.n else 0.0
        self.df: dict[str, int] = {}
        self.tf: list[dict[str, int]] = []
        for doc in documents:
            counts: dict[str, int] = {}
            for token in doc:
                counts[token] = counts.get(token, 0) + 1
            self.tf.append(counts)
            for token in counts:
                self.df[token] = self.df.get(token, 0) + 1

    def scores(self, query: list[str]) -> list[float]:
        results = []
        for index, counts in enumerate(self.tf):
            score = 0.0
            length = len(self.docs[index]) or 1
            for token in query:
                freq = counts.get(token)
                if not freq:
                    continue
                df = self.df.get(token, 0)
                idf = math.log(1 + (self.n - df + 0.5) / (df + 0.5))
                denom = freq + self.k1 * (1 - self.b + self.b * length / (self.avg or 1))
                score += idf * (freq * (self.k1 + 1) / denom)
            results.append(score)
        return results


def _segment(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip(".")[:80] or "unknown"
    return f"{slug}-{hashlib.sha256(value.encode()).hexdigest()[:10]}"
