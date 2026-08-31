"""Boundary-metadata closure checks for inference engines."""

from __future__ import annotations

import ast
from pathlib import Path

import openjarvis.engine  # noqa: F401  # trigger available engine registration
from openjarvis.core.config import JarvisConfig
from openjarvis.core.inference_boundaries import ENGINE_ENDPOINT_SPECS
from openjarvis.core.registry import EngineRegistry
from openjarvis.engine.nim import NIMEngine
from openjarvis.engine.ollama import OllamaEngine
from openjarvis.engine.openai_compat_engines import _ENGINES

_ENGINE_SOURCE_DIR = (
    Path(__file__).resolve().parents[2] / "src" / "openjarvis" / "engine"
)
_AVAILABLE_REGISTERED_ENGINE_KEYS = frozenset(EngineRegistry.keys())


def _get_dotted(obj, dotted_path: str):  # noqa: ANN001, ANN202
    current = obj
    for part in dotted_path.split("."):
        current = getattr(current, part)
    return current


def _literal_registry_keys_from_source() -> set[str]:
    """Find literal engine registration keys without importing optional modules."""

    keys: set[str] = set()
    for path in _ENGINE_SOURCE_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "EngineRegistry"
                and func.attr in {"register", "register_value"}
            ):
                continue
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                keys.add(first_arg.value)
    return keys


def test_every_engine_registration_surface_has_boundary_metadata() -> None:
    source_keys = _literal_registry_keys_from_source() | set(_ENGINES)
    missing = source_keys - set(ENGINE_ENDPOINT_SPECS)

    assert not missing, f"engine boundary metadata missing for: {sorted(missing)}"


def test_every_available_registered_engine_has_boundary_metadata() -> None:
    missing = _AVAILABLE_REGISTERED_ENGINE_KEYS - set(ENGINE_ENDPOINT_SPECS)

    assert not missing, f"engine boundary metadata missing for: {sorted(missing)}"


def test_compatible_engine_defaults_match_boundary_metadata() -> None:
    for key, (_class_name, default_host, _api_prefix) in _ENGINES.items():
        assert ENGINE_ENDPOINT_SPECS[key].default_endpoint == default_host


def test_explicit_config_defaults_match_boundary_metadata() -> None:
    config = JarvisConfig()
    for key, spec in ENGINE_ENDPOINT_SPECS.items():
        if spec.config_path is None or spec.default_endpoint is None:
            continue
        configured = str(_get_dotted(config, spec.config_path) or "").strip()
        if configured:
            assert configured == spec.default_endpoint, key


def test_native_engine_defaults_match_boundary_metadata() -> None:
    assert (
        ENGINE_ENDPOINT_SPECS["ollama"].default_endpoint == OllamaEngine._DEFAULT_HOST
    )
    assert ENGINE_ENDPOINT_SPECS["nim"].default_endpoint == NIMEngine._default_host
