"""Closure tests for registry-backed security surfaces."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path
from typing import Mapping

from openjarvis.core.inference_boundaries import ENGINE_ENDPOINT_SPECS
from openjarvis.security.surface_manifest import (
    ACCOUNTED_DYNAMIC_REGISTRATION_SITES,
    DELEGATED_SECURITY_REGISTRIES,
    LEGACY_UNMODELED_SURFACE_EXEMPTIONS,
    MODELED_SURFACE_KEYS,
    PER_KEY_SECURITY_REGISTRIES,
    surface_disposition,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SOURCE_ROOT = _REPO_ROOT / "src" / "openjarvis"
_REGISTRY_SOURCE = _SOURCE_ROOT / "core" / "registry.py"


def _base_class_name(base: ast.expr) -> str | None:
    if isinstance(base, ast.Subscript):
        return _base_class_name(base.value)
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Attribute):
        return base.attr
    return None


def _registry_class_names() -> set[str]:
    tree = ast.parse(
        _REGISTRY_SOURCE.read_text(encoding="utf-8"),
        filename=str(_REGISTRY_SOURCE),
    )
    classes = {
        node.name: {
            name for base in node.bases if (name := _base_class_name(base)) is not None
        }
        for node in tree.body
        if isinstance(node, ast.ClassDef)
    }

    registry_classes: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, bases in classes.items():
            if name in registry_classes:
                continue
            if "RegistryBase" in bases or bases & registry_classes:
                registry_classes.add(name)
                changed = True
    return registry_classes


def _qualified_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        if parent is not None:
            return f"{parent}.{node.attr}"
    return None


def _registry_imports(
    tree: ast.AST,
    registry_names: set[str],
) -> tuple[dict[str, str], set[str]]:
    direct_aliases = {name: name for name in registry_names}
    module_aliases: set[str] = {"openjarvis.core.registry"}

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module == "openjarvis.core.registry":
                for imported in node.names:
                    if imported.name in registry_names:
                        direct_aliases[imported.asname or imported.name] = imported.name
            elif node.module == "openjarvis.core":
                for imported in node.names:
                    if imported.name == "registry":
                        module_aliases.add(imported.asname or imported.name)
        elif isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name == "openjarvis.core.registry" and imported.asname:
                    module_aliases.add(imported.asname)

    return direct_aliases, module_aliases


def _registry_from_owner(
    owner: ast.expr,
    registry_names: set[str],
    direct_aliases: Mapping[str, str],
    module_aliases: set[str],
) -> str | None:
    if isinstance(owner, ast.Name):
        return direct_aliases.get(owner.id)

    if isinstance(owner, ast.Attribute) and owner.attr in registry_names:
        module_name = _qualified_name(owner.value)
        if module_name in module_aliases:
            return owner.attr

    return None


def _registration_inventory() -> tuple[set[tuple[str, str]], set[tuple[str, str, str]]]:
    registry_names = _registry_class_names()
    literal: set[tuple[str, str]] = set()
    dynamic: set[tuple[str, str, str]] = set()

    for path in sorted(_SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        direct_aliases, module_aliases = _registry_imports(tree, registry_names)
        relative_path = path.relative_to(_REPO_ROOT).as_posix()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and func.attr in {"register", "register_value"}
            ):
                continue
            registry = _registry_from_owner(
                func.value,
                registry_names,
                direct_aliases,
                module_aliases,
            )
            if registry is None:
                continue

            key_node = node.args[0]
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                literal.add((registry, key_node.value))
            else:
                dynamic.add((registry, relative_path, ast.unparse(key_node)))

    return literal, dynamic


def _flatten(mapping: Mapping[str, frozenset[str]]) -> set[tuple[str, str]]:
    return {(registry, key) for registry, keys in mapping.items() for key in keys}


def test_every_registry_has_an_explicit_security_accounting_policy() -> None:
    registry_classes = _registry_class_names()
    per_key = set(PER_KEY_SECURITY_REGISTRIES)
    delegated = set(DELEGATED_SECURITY_REGISTRIES)

    assert per_key.isdisjoint(delegated)
    assert registry_classes == per_key | delegated


def test_manifest_categories_reference_only_per_key_registries() -> None:
    per_key = set(PER_KEY_SECURITY_REGISTRIES)
    dynamic_registries = {
        registry for registry, _path, _expr in ACCOUNTED_DYNAMIC_REGISTRATION_SITES
    }

    assert set(MODELED_SURFACE_KEYS) <= per_key
    assert set(LEGACY_UNMODELED_SURFACE_EXEMPTIONS) <= per_key
    assert dynamic_registries <= per_key


def test_every_literal_per_key_surface_is_modeled_or_explicitly_exempted() -> None:
    literal, _dynamic = _registration_inventory()
    per_key_literal = {
        item for item in literal if item[0] in PER_KEY_SECURITY_REGISTRIES
    }
    modeled = _flatten(MODELED_SURFACE_KEYS)
    legacy = _flatten(LEGACY_UNMODELED_SURFACE_EXEMPTIONS)

    missing = per_key_literal - modeled - legacy
    assert not missing, f"security disposition missing for: {sorted(missing)}"

    stale_legacy = legacy - per_key_literal
    assert not stale_legacy, f"remove stale legacy exemptions: {sorted(stale_legacy)}"


def test_modeled_and_legacy_surfaces_do_not_overlap() -> None:
    overlap = _flatten(MODELED_SURFACE_KEYS) & _flatten(
        LEGACY_UNMODELED_SURFACE_EXEMPTIONS
    )

    assert not overlap, f"surface is both modeled and exempted: {sorted(overlap)}"


def test_dynamic_per_key_registration_sites_are_explicitly_accounted_for() -> None:
    _literal, dynamic = _registration_inventory()
    per_key_dynamic = {
        item for item in dynamic if item[0] in PER_KEY_SECURITY_REGISTRIES
    }

    assert per_key_dynamic == set(ACCOUNTED_DYNAMIC_REGISTRATION_SITES)


def test_engine_modeled_surfaces_are_the_endpoint_boundary_inventory() -> None:
    assert MODELED_SURFACE_KEYS["EngineRegistry"] == frozenset(ENGINE_ENDPOINT_SPECS)


def test_surface_disposition_distinguishes_modeled_delegated_and_legacy() -> None:
    assert surface_disposition("EngineRegistry", "ollama") == "modeled"
    assert surface_disposition("ModelRegistry", "any-model-id") == "delegated"
    assert surface_disposition("ToolRegistry", "file_read") == "legacy-exemption"
    assert surface_disposition("ToolRegistry", "future-tool") is None


def test_surface_manifest_import_does_not_load_runtime_primitive_packages() -> None:
    runtime_prefixes = (
        "openjarvis.agents",
        "openjarvis.channels",
        "openjarvis.connectors",
        "openjarvis.engine",
        "openjarvis.learning",
        "openjarvis.mining",
        "openjarvis.speech",
        "openjarvis.tools",
    )
    code = "\n".join(
        [
            "import sys",
            "import openjarvis.security.surface_manifest",
            f"prefixes = {runtime_prefixes!r}",
            "loaded = sorted(",
            "    name for name in sys.modules if name.startswith(prefixes)",
            ")",
            "assert not loaded, loaded",
        ]
    )

    subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )
