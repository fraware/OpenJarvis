"""Import-safe inference endpoint trust-boundary metadata.

This module contains no engine imports and performs no network I/O.  It exists so
runtime engine selection and static data-boundary diagnostics can classify the
same inference endpoint semantics without importing engine packages or probing
endpoints.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping
from urllib.parse import urlsplit


class EndpointBoundary(str, Enum):
    """Trust boundary of an inference endpoint relative to this host."""

    IN_PROCESS = "in-process"
    LOCAL_HOST = "local-host"
    EXTERNAL_NETWORK = "external-network"
    VENDOR_CLOUD = "vendor-cloud"
    UNKNOWN = "unknown"

    @property
    def leaves_local_host(self) -> bool | None:
        """Whether requests cross the local-host boundary, when known."""

        if self in {EndpointBoundary.IN_PROCESS, EndpointBoundary.LOCAL_HOST}:
            return False
        if self in {
            EndpointBoundary.EXTERNAL_NETWORK,
            EndpointBoundary.VENDOR_CLOUD,
        }:
            return True
        return None


@dataclass(frozen=True, slots=True)
class EngineEndpointSpec:
    """Static endpoint-resolution semantics for a registered engine key."""

    config_path: str | None = None
    env_var: str | None = None
    default_endpoint: str | None = None
    fixed_boundary: EndpointBoundary | None = None
    default_boundary: EndpointBoundary | None = None


@dataclass(frozen=True, slots=True)
class EngineBoundaryResolution:
    """Redaction-safe result of resolving one configured engine boundary."""

    engine_key: str
    boundary: EndpointBoundary
    source: str

    @property
    def leaves_local_host(self) -> bool | None:
        return self.boundary.leaves_local_host


# Keep these defaults aligned with the constructors used by the engine layer.
# Values are used only to classify endpoint locality; callers should not emit
# configured endpoint values in diagnostics.
ENGINE_ENDPOINT_SPECS: Mapping[str, EngineEndpointSpec] = {
    "afm": EngineEndpointSpec(fixed_boundary=EndpointBoundary.IN_PROCESS),
    "gemma_cpp": EngineEndpointSpec(fixed_boundary=EndpointBoundary.IN_PROCESS),
    "cloud": EngineEndpointSpec(fixed_boundary=EndpointBoundary.VENDOR_CLOUD),
    "litellm": EngineEndpointSpec(fixed_boundary=EndpointBoundary.VENDOR_CLOUD),
    "nim": EngineEndpointSpec(
        env_var="NIM_HOST",
        default_endpoint="https://integrate.api.nvidia.com",
        default_boundary=EndpointBoundary.VENDOR_CLOUD,
    ),
    "ollama": EngineEndpointSpec(
        config_path="engine.ollama.host",
        env_var="OLLAMA_HOST",
        default_endpoint="http://localhost:11434",
    ),
    "vllm": EngineEndpointSpec(
        config_path="engine.vllm.host",
        env_var="VLLM_HOST",
        default_endpoint="http://localhost:8000",
    ),
    "sglang": EngineEndpointSpec(
        config_path="engine.sglang.host",
        env_var="SGLANG_HOST",
        default_endpoint="http://localhost:30000",
    ),
    "llamacpp": EngineEndpointSpec(
        config_path="engine.llamacpp.host",
        env_var="LLAMACPP_HOST",
        default_endpoint="http://localhost:8080",
    ),
    "mlx": EngineEndpointSpec(
        config_path="engine.mlx.host",
        env_var="MLX_HOST",
        default_endpoint="http://localhost:8080",
    ),
    "lmstudio": EngineEndpointSpec(
        config_path="engine.lmstudio.host",
        env_var="LMSTUDIO_HOST",
        default_endpoint="http://localhost:1234",
    ),
    "exo": EngineEndpointSpec(
        config_path="engine.exo.host",
        env_var="EXO_HOST",
        default_endpoint="http://localhost:52415",
    ),
    "nexa": EngineEndpointSpec(
        config_path="engine.nexa.host",
        env_var="NEXA_HOST",
        default_endpoint="http://localhost:18181",
    ),
    "uzu": EngineEndpointSpec(
        config_path="engine.uzu.host",
        env_var="UZU_HOST",
        default_endpoint="http://localhost:8000",
    ),
    "apple_fm": EngineEndpointSpec(
        config_path="engine.apple_fm.host",
        env_var="APPLE_FM_HOST",
        default_endpoint="http://localhost:8079",
    ),
    "lemonade": EngineEndpointSpec(
        config_path="engine.lemonade.host",
        env_var="LEMONADE_HOST",
        default_endpoint="http://localhost:13305",
    ),
}


def classify_endpoint(endpoint: str | None) -> EndpointBoundary:
    """Classify an endpoint without returning or logging its value."""

    text = str(endpoint or "").strip()
    if not text:
        return EndpointBoundary.UNKNOWN

    # ``urlsplit`` treats a bare host as a path. Prefix ``//`` only for parsing
    # so hostname extraction also works for values such as ``localhost:11434``.
    parsed = urlsplit(text if "://" in text else f"//{text}")
    hostname = parsed.hostname
    if not hostname:
        return EndpointBoundary.UNKNOWN

    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return EndpointBoundary.LOCAL_HOST
    try:
        if ipaddress.ip_address(normalized).is_loopback:
            return EndpointBoundary.LOCAL_HOST
    except ValueError:
        pass
    return EndpointBoundary.EXTERNAL_NETWORK


def _get_dotted(obj: Any, dotted_path: str) -> Any:
    current = obj
    for part in dotted_path.split("."):
        if current is None:
            return None
        current = getattr(current, part, None)
    return current


def resolve_engine_boundary(
    engine_key: str | None,
    config: Any | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> EngineBoundaryResolution:
    """Resolve configured endpoint semantics without importing an engine.

    Resolution mirrors runtime precedence for known engines: fixed semantics,
    then a non-empty config host, then a non-empty environment host, then the
    engine default.  Only the source and boundary class are returned.
    """

    key = str(engine_key or "").strip().lower()
    spec = ENGINE_ENDPOINT_SPECS.get(key)
    if spec is None:
        return EngineBoundaryResolution(key, EndpointBoundary.UNKNOWN, "unclassified")

    if spec.fixed_boundary is not None:
        return EngineBoundaryResolution(key, spec.fixed_boundary, "fixed")

    if spec.config_path and config is not None:
        configured = str(_get_dotted(config, spec.config_path) or "").strip()
        if configured:
            return EngineBoundaryResolution(
                key,
                classify_endpoint(configured),
                spec.config_path,
            )

    environment = os.environ if environ is None else environ
    if spec.env_var:
        env_value = str(environment.get(spec.env_var, "") or "").strip()
        if env_value:
            return EngineBoundaryResolution(
                key,
                classify_endpoint(env_value),
                spec.env_var,
            )

    if spec.default_boundary is not None:
        return EngineBoundaryResolution(key, spec.default_boundary, "default")
    if spec.default_endpoint:
        return EngineBoundaryResolution(
            key,
            classify_endpoint(spec.default_endpoint),
            "default",
        )
    return EngineBoundaryResolution(key, EndpointBoundary.UNKNOWN, "unclassified")


def boundary_from_engine_instance(
    engine_key: str,
    engine: Any,
) -> EndpointBoundary:
    """Classify the endpoint actually selected by an instantiated engine.

    Unknown engine types remain ``UNKNOWN`` unless they explicitly mark
    themselves cloud-bound or expose a host.  This prevents a new engine from
    being silently treated as local merely because ``InferenceEngine.is_cloud``
    defaults to ``False``.
    """

    key = str(engine_key or "").strip().lower()
    if bool(getattr(engine, "is_cloud", False)):
        return EndpointBoundary.VENDOR_CLOUD

    spec = ENGINE_ENDPOINT_SPECS.get(key)
    if spec and spec.fixed_boundary is not None:
        return spec.fixed_boundary

    host = getattr(engine, "_host", None)
    if host:
        if (
            key == "nim"
            and spec is not None
            and spec.default_endpoint
            and str(host).rstrip("/") == spec.default_endpoint.rstrip("/")
        ):
            return EndpointBoundary.VENDOR_CLOUD
        return classify_endpoint(str(host))

    if spec and spec.default_boundary is not None:
        return spec.default_boundary
    if spec and spec.default_endpoint:
        return classify_endpoint(spec.default_endpoint)
    return EndpointBoundary.UNKNOWN


def same_host_egress_class(
    left: EndpointBoundary,
    right: EndpointBoundary,
) -> bool:
    """Return whether two known boundaries agree on leaving the local host."""

    left_egress = left.leaves_local_host
    right_egress = right.leaves_local_host
    return (
        left_egress is not None
        and right_egress is not None
        and left_egress == right_egress
    )


__all__ = [
    "ENGINE_ENDPOINT_SPECS",
    "EndpointBoundary",
    "EngineBoundaryResolution",
    "EngineEndpointSpec",
    "boundary_from_engine_instance",
    "classify_endpoint",
    "resolve_engine_boundary",
    "same_host_egress_class",
]
