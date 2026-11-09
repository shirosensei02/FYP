"""Parse JavaScript and TypeScript into symbols, imports, calls, and extends.

Tree-sitter supplies the syntax tree. Bindings then connect a local alias
such as `scrub` in `const { helper: scrub } = require("./b")` to the imported
name `helper`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

try:
    import tree_sitter_javascript as _ts_javascript
    import tree_sitter_typescript as _ts_typescript
    from tree_sitter import Language, Parser
except ImportError:  # pragma: no cover - exercised only when the parser is absent
    _ts_javascript = None
    _ts_typescript = None
    Language = None
    Parser = None


@dataclass(frozen=True)
class JsSymbol:
    name: str
    kind: str
    qualified: str
    start: int
    end: int
    export_names: tuple[str, ...]


@dataclass(frozen=True)
class JsBinding:
    local: str
    specifier: str
    imported: str


@dataclass(frozen=True)
class JsCall:
    owner: str
    name: str
    object: str
    is_new: bool = False


@dataclass(frozen=True)
class JsExtend:
    child: str
    parent: str


@dataclass
class JsFile:
    path: str
    symbols: list[JsSymbol] = field(default_factory=list)
    bindings: list[JsBinding] = field(default_factory=list)
    calls: list[JsCall] = field(default_factory=list)
    extends: list[JsExtend] = field(default_factory=list)


class _Walk:
    def __init__(self, text: str):
        self.text = text
        self.encoded = text.encode("utf-8")
        self.chars = _byte_to_char(text)
        self.file = JsFile(path="")
        self.exported = False
        self.default_export = False
        self.owner = ""
        self.stack: list[str] = []
        self.object_name = ""

    def position(self, byte_index: int) -> int:
        return self.chars.get(byte_index, len(self.text))


_PARSERS: dict[str, object] = {}


def parser_available() -> bool:
    return Parser is not None


def parse_javascript(relative: str, text: str) -> JsFile | None:
    """Return symbols and bindings for one source file, or None when it cannot be parsed."""
    if not parser_available() or not text.strip():
        return None
    parser = _parser(relative)
    if parser is None:
        return None
    tree = parser.parse(text.encode("utf-8"))
    walk = _Walk(text)
    walk.file.path = relative
    _visit(tree.root_node, walk)
    if tree.root_node.has_error and not walk.file.symbols and not walk.file.bindings:
        return None
    return walk.file


def _parser(relative: str):
    suffix = relative.rsplit(".", 1)[-1].lower() if "." in relative else "js"
    cached = _PARSERS.get(suffix)
    if cached is not None:
        return cached
    if suffix == "ts":
        language = Language(_ts_typescript.language_typescript())
    elif suffix == "tsx":
        language = Language(_ts_typescript.language_tsx())
    elif suffix in {"js", "jsx", "mjs", "cjs"}:
        language = Language(_ts_javascript.language())
    else:
        return None
    parser = Parser(language)
    _PARSERS[suffix] = parser
    return parser


def _visit(node, walk: _Walk) -> None:
    kind = node.type
    if kind == "export_statement":
        exported = walk.exported
        default_export = walk.default_export
        walk.exported = True
        walk.default_export = any(child.type == "default" for child in node.children)
        for child in node.children:
            _visit(child, walk)
        walk.exported = exported
        walk.default_export = default_export
        _collect_reexport(node, walk)
        return
    if kind == "import_statement":
        _collect_import(node, walk)
        return
    if kind == "class_declaration":
        _collect_class(node, walk)
        return
    if kind == "function_declaration":
        _collect_function(node, walk, _declaration_name(node))
        return
    if kind == "method_definition":
        _collect_method(node, walk)
        return
    if kind == "pair":
        _collect_pair(node, walk)
        return
    if kind == "variable_declarator":
        _collect_declarator(node, walk)
        return
    if kind == "assignment_expression":
        _collect_assignment(node, walk)
        return
    if kind == "call_expression":
        _collect_call(node, walk)
        arguments = _child(node, "arguments")
        if arguments is not None:
            for child in arguments.children:
                _visit(child, walk)
        return
    if kind == "new_expression":
        _collect_new(node, walk)
        for child in node.children:
            if child.type == "arguments":
                for item in child.children:
                    _visit(item, walk)
        return
    for child in node.children:
        _visit(child, walk)


def _qualify(walk: _Walk, name: str) -> str:
    if walk.stack:
        return ".".join([*walk.stack, name])
    return name


def _enter(walk: _Walk, qualified: str, *, function: bool):
    """Push the qualified path so nested functions stay under their parent."""
    saved = (list(walk.stack), walk.owner, walk.object_name)
    walk.stack = [part for part in qualified.split(".") if part]
    walk.object_name = ""
    if function:
        walk.owner = qualified
    return saved


def _leave(walk: _Walk, saved) -> None:
    walk.stack, walk.owner, walk.object_name = saved


def _collect_class(node, walk: _Walk) -> None:
    name = _declaration_name(node)
    if not name:
        return
    qualified = _qualify(walk, name)
    _add_symbol(node, walk, name, "class", qualified)
    saved = _enter(walk, qualified, function=False)
    heritage = _child(node, "class_heritage")
    if heritage is not None:
        parent = _heritage_name(heritage)
        if parent:
            walk.file.extends.append(JsExtend(child=qualified, parent=parent))
    body = _child(node, "class_body")
    if body is not None:
        for child in body.children:
            _visit(child, walk)
    _leave(walk, saved)


def _collect_function(node, walk: _Walk, name: str) -> None:
    if not name:
        return
    qualified = _qualify(walk, name)
    _add_symbol(node, walk, name, "function", qualified)
    saved = _enter(walk, qualified, function=True)
    body = _child(node, "statement_block")
    if body is not None:
        for child in body.children:
            _visit(child, walk)
    _leave(walk, saved)


def _collect_method(node, walk: _Walk) -> None:
    name = _declaration_name(node)
    if not name:
        return
    qualified = f"{walk.object_name}.{name}" if walk.object_name else _qualify(walk, name)
    _add_symbol(node, walk, name, "function", qualified)
    saved = _enter(walk, qualified, function=True)
    body = _child(node, "statement_block")
    if body is not None:
        for child in body.children:
            _visit(child, walk)
    _leave(walk, saved)


def _collect_declarator(node, walk: _Walk) -> None:
    value = _declarator_value(node)
    specifier = _require_specifier(value) if value is not None else None
    target = node.children[0] if node.children else None
    if target is None:
        return
    if specifier and target.type == "object_pattern":
        for imported, local in _pattern_bindings(target):
            walk.file.bindings.append(JsBinding(local=local, specifier=specifier, imported=imported))
        return
    if specifier and target.type == "identifier":
        walk.file.bindings.append(JsBinding(local=_text(target), specifier=specifier, imported="*"))
        return
    if value is not None and value.type in {"function_expression", "arrow_function", "function"} and target.type == "identifier":
        _collect_function_value(target, value, walk, _text(target))
        return
    if value is not None and value.type == "object" and target.type == "identifier":
        _visit_named_object(value, walk, _text(target))
        return
    if value is not None:
        _visit(value, walk)


def _collect_assignment(node, walk: _Walk) -> None:
    left = node.children[0] if node.children else None
    value = _assignment_value(node)
    if left is not None and value is not None and left.type == "identifier" and value.type == "object":
        _visit_named_object(value, walk, _text(left))
        return
    if left is None or value is None or left.type != "member_expression":
        for child in node.children:
            _visit(child, walk)
        return
    export_name = _export_member_name(left)
    if export_name and value.type == "object":
        _visit_named_object(value, walk, export_name)
        return
    if export_name and value.type in {"function_expression", "arrow_function", "function"}:
        function_name = _declaration_name(value) or export_name
        previous = walk.exported
        walk.exported = True
        _collect_function_value(value, value, walk, function_name, export_name=export_name)
        walk.exported = previous
        return
    if _is_module_exports(left) and value.type in {"function_expression", "arrow_function", "function"}:
        function_name = _declaration_name(value) or "default"
        previous_export = walk.exported
        previous_default = walk.default_export
        walk.exported = True
        walk.default_export = True
        _collect_function_value(value, value, walk, function_name, export_name=function_name)
        walk.exported = previous_export
        walk.default_export = previous_default
        return
    for child in node.children:
        _visit(child, walk)


def _visit_named_object(node, walk: _Walk, name: str) -> None:
    """Methods on a named object are `api.stat`, contained by the file."""
    previous = walk.object_name
    walk.object_name = name
    for child in node.children:
        _visit(child, walk)
    walk.object_name = previous


def _collect_pair(node, walk: _Walk) -> None:
    key, value = _pair_key_value(node)
    name = _property_text(key)
    if value is None:
        return
    if name and value.type == "object":
        nested = f"{walk.object_name}.{name}" if walk.object_name else name
        _visit_named_object(value, walk, nested)
        return
    if name and value.type in {"function_expression", "arrow_function", "function"}:
        _collect_function_value(value, value, walk, name)
        return
    _visit(value, walk)


def _collect_function_value(node, value, walk: _Walk, name: str, export_name: str | None = None) -> None:
    if name == "default":
        qualified = "default"
    elif walk.object_name:
        qualified = f"{walk.object_name}.{name}"
    else:
        qualified = _qualify(walk, name)
    names = [export_name or name]
    if walk.default_export and "default" not in names:
        names.append("default")
    start = walk.position(value.start_byte)
    end = walk.position(value.end_byte)
    if not any(symbol.qualified == qualified and symbol.start == start for symbol in walk.file.symbols):
        walk.file.symbols.append(JsSymbol(
            name=name,
            kind="function",
            qualified=qualified,
            start=start,
            end=end,
            export_names=tuple(dict.fromkeys(names)),
        ))
    saved = _enter(walk, qualified, function=True)
    for child in value.children:
        if child.type in {"formal_parameters", "identifier", "property_identifier"}:
            continue
        _visit(child, walk)
    _leave(walk, saved)


def _collect_import(node, walk: _Walk) -> None:
    specifier = ""
    for child in node.children:
        if child.type == "string":
            specifier = _string_value(child)
    if not specifier:
        return
    clause = _child(node, "import_clause")
    if clause is None:
        walk.file.bindings.append(JsBinding(local="", specifier=specifier, imported="*"))
        return
    for child in clause.children:
        if child.type == "identifier":
            walk.file.bindings.append(JsBinding(local=_text(child), specifier=specifier, imported="default"))
        elif child.type == "namespace_import":
            local = _last_identifier(child)
            if local:
                walk.file.bindings.append(JsBinding(local=local, specifier=specifier, imported="*"))
        elif child.type == "named_imports":
            for specifier_node in child.children:
                if specifier_node.type != "import_specifier":
                    continue
                identifiers = [item for item in specifier_node.children if item.type == "identifier"]
                if not identifiers:
                    continue
                imported = _text(identifiers[0])
                local = _text(identifiers[-1])
                walk.file.bindings.append(JsBinding(local=local, specifier=specifier, imported=imported))


def _collect_reexport(node, walk: _Walk) -> None:
    specifier = ""
    for child in node.children:
        if child.type == "string":
            specifier = _string_value(child)
    if not specifier:
        return
    for child in node.children:
        if child.type != "export_clause":
            continue
        for item in child.children:
            if item.type != "export_specifier":
                continue
            identifiers = [part for part in item.children if part.type == "identifier"]
            if identifiers:
                walk.file.bindings.append(JsBinding(local="", specifier=specifier, imported=_text(identifiers[0])))


def _collect_call(node, walk: _Walk) -> None:
    specifier = _require_specifier(node)
    if specifier:
        walk.file.bindings.append(JsBinding(local="", specifier=specifier, imported="*"))
        return
    if not walk.owner:
        return
    callee = node.children[0] if node.children else None
    if callee is None:
        return
    if callee.type == "identifier":
        name = _text(callee)
        if name not in {"require", "import"}:
            walk.file.calls.append(JsCall(owner=walk.owner, name=name, object=""))
        return
    if callee.type == "member_expression":
        obj, prop = _member(callee)
        if obj and prop and obj != "exports" and not (obj == "module" and prop == "exports"):
            walk.file.calls.append(JsCall(owner=walk.owner, name=prop, object=obj))


def _collect_new(node, walk: _Walk) -> None:
    if not walk.owner:
        return
    for child in node.children:
        if child.type == "identifier":
            walk.file.calls.append(JsCall(owner=walk.owner, name=_text(child), object="", is_new=True))
            return
        if child.type == "member_expression":
            obj, prop = _member(child)
            if obj and prop:
                walk.file.calls.append(JsCall(owner=walk.owner, name=prop, object=obj, is_new=True))
            return


def _add_symbol(node, walk: _Walk, name: str, kind: str, qualified: str) -> None:
    names = [name]
    if walk.exported:
        names.append(name)
    if walk.default_export:
        names.append("default")
    walk.file.symbols.append(JsSymbol(
        name=name,
        kind=kind,
        qualified=qualified,
        start=walk.position(node.start_byte),
        end=walk.position(node.end_byte),
        export_names=tuple(dict.fromkeys(names)),
    ))


def _pattern_bindings(pattern) -> list[tuple[str, str]]:
    found = []
    for child in pattern.children:
        if child.type == "pair_pattern":
            identifiers = [item for item in child.children if item.type in {"property_identifier", "identifier"}]
            if len(identifiers) >= 2:
                found.append((_text(identifiers[0]), _text(identifiers[-1])))
            elif identifiers:
                found.append((_text(identifiers[0]), _text(identifiers[0])))
        elif child.type == "shorthand_property_identifier_pattern":
            name = _text(child)
            found.append((name, name))
    return found


def _declarator_value(node):
    seen_equals = False
    for child in node.children:
        if child.type == "=":
            seen_equals = True
            continue
        if seen_equals:
            return child
    return None


def _pair_key_value(node):
    key = None
    seen = False
    for child in node.children:
        if child.type == ":":
            seen = True
            continue
        if not seen and key is None:
            key = child
            continue
        if seen:
            return key, child
    return key, None


def _property_text(node) -> str:
    if node is None:
        return ""
    if node.type == "string":
        return _string_value(node)
    if node.type in {"property_identifier", "identifier"}:
        return _text(node)
    return ""


def _assignment_value(node):
    seen_equals = False
    for child in node.children:
        if child.type == "=":
            seen_equals = True
            continue
        if seen_equals:
            return child
    return None


def _require_specifier(node) -> str | None:
    if node is None or node.type != "call_expression" or not node.children:
        return None
    callee = node.children[0]
    if callee.type != "identifier" or _text(callee) != "require":
        return None
    arguments = _child(node, "arguments")
    if arguments is None:
        return None
    for child in arguments.children:
        if child.type == "string":
            return _string_value(child)
    return None


def _export_member_name(node) -> str:
    obj, prop = _member(node)
    if obj == "exports" and prop and prop != "exports":
        return prop
    if obj == "module":
        return ""
    return ""


def _is_module_exports(node) -> bool:
    obj, prop = _member(node)
    return obj == "module" and prop == "exports"


def _member(node) -> tuple[str, str]:
    identifiers = [child for child in node.children if child.type in {"identifier", "property_identifier"}]
    if len(identifiers) >= 2:
        return _text(identifiers[0]), _text(identifiers[1])
    return "", ""


def _heritage_name(node) -> str:
    for child in node.children:
        if child.type == "identifier":
            return _text(child)
        if child.type == "member_expression":
            _obj, prop = _member(child)
            return prop
    return ""


def _declaration_name(node) -> str:
    for child in node.children:
        if child.type in {"identifier", "property_identifier"}:
            return _text(child)
    return ""


def _last_identifier(node) -> str:
    identifiers = [child for child in node.children if child.type == "identifier"]
    if not identifiers:
        return ""
    return _text(identifiers[-1])


def _string_value(node) -> str:
    for child in node.children:
        if child.type == "string_fragment":
            return _text(child)
    text = _text(node)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"', "`"}:
        return text[1:-1]
    return text


def _child(node, kind: str):
    for child in node.children:
        if child.type == kind:
            return child
    return None


def _text(node) -> str:
    return node.text.decode("utf-8")


def _byte_to_char(text: str) -> dict[int, int]:
    mapping = {0: 0}
    byte = 0
    for index, char in enumerate(text):
        mapping[byte] = index
        byte += len(char.encode("utf-8"))
    mapping[byte] = len(text)
    return mapping
