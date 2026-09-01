from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

TARGETS = {
    "AgentRegistry",
    "BenchmarkRegistry",
    "ChannelRegistry",
    "CompressionRegistry",
    "ConnectorRegistry",
    "EngineRegistry",
    "FactStoreRegistry",
    "LearningRegistry",
    "MemoryRegistry",
    "MinerRegistry",
    "ModelRegistry",
    "RouterPolicyRegistry",
    "SkillRegistry",
    "SpeechRegistry",
    "TTSRegistry",
    "ToolRegistry",
}

literal: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
dynamic: dict[str, list[tuple[str, int, str]]] = defaultdict(list)

for path in sorted(Path("src/openjarvis").rglob("*.py")):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in {"register", "register_value"}:
            continue
        owner = func.value
        if not isinstance(owner, ast.Name) or owner.id not in TARGETS:
            continue
        registry = owner.id
        if not node.args:
            dynamic[registry].append((str(path), node.lineno, "<missing-key>"))
            continue
        key_node = node.args[0]
        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
            literal[registry].append((str(path), node.lineno, key_node.value))
        else:
            try:
                rendered = ast.unparse(key_node)
            except Exception:
                rendered = type(key_node).__name__
            dynamic[registry].append((str(path), node.lineno, rendered))

for registry in sorted(TARGETS):
    print(f"## {registry}")
    keys = sorted({key for _, _, key in literal[registry]})
    print("literal-count", len(keys))
    for key in keys:
        locations = [f"{path}:{line}" for path, line, item in literal[registry] if item == key]
        print(f"LITERAL {key!r} {' '.join(locations)}")
    sites = sorted(dynamic[registry])
    print("dynamic-count", len(sites))
    for path, line, rendered in sites:
        print(f"DYNAMIC {path}:{line} {rendered}")
