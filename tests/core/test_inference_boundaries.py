"""Tests for import-safe inference endpoint boundary metadata."""

from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace

from openjarvis.core.config import JarvisConfig
from openjarvis.core.inference_boundaries import (
    EndpointBoundary,
    boundary_from_engine_instance,
    classify_endpoint,
    resolve_engine_boundary,
    same_host_egress_class,
)


def test_classify_endpoint_distinguishes_local_host_from_network() -> None:
    assert classify_endpoint("http://localhost:11434") is EndpointBoundary.LOCAL_HOST
    assert classify_endpoint("localhost:11434") is EndpointBoundary.LOCAL_HOST
    assert classify_endpoint("http://127.0.0.1:8000") is EndpointBoundary.LOCAL_HOST
    assert classify_endpoint("http://[::1]:8000") is EndpointBoundary.LOCAL_HOST
    assert (
        classify_endpoint("https://inference.example.test")
        is EndpointBoundary.EXTERNAL_NETWORK
    )
    assert (
        classify_endpoint("http://10.0.0.4:8000")
        is EndpointBoundary.EXTERNAL_NETWORK
    )
    assert classify_endpoint("http://0.0.0.0:8000") is EndpointBoundary.UNKNOWN
    assert classify_endpoint("http://[::]:8000") is EndpointBoundary.UNKNOWN
    assert classify_endpoint("") is EndpointBoundary.UNKNOWN


def test_malformed_endpoint_is_unknown_instead_of_raising() -> None:
    assert classify_endpoint("http://[::1") is EndpointBoundary.UNKNOWN


def test_boundary_metadata_import_does_not_load_engine_package() -> None:
    code = (
        "import sys; "
        "import openjarvis.core.inference_boundaries; "
        "assert 'openjarvis.engine' not in sys.modules"
    )

    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_fixed_engine_boundaries_are_explicit() -> None:
    assert resolve_engine_boundary("afm").boundary is EndpointBoundary.IN_PROCESS
    assert resolve_engine_boundary("gemma_cpp").boundary is EndpointBoundary.IN_PROCESS
    assert resolve_engine_boundary("cloud").boundary is EndpointBoundary.VENDOR_CLOUD
    assert resolve_engine_boundary("litellm").boundary is EndpointBoundary.VENDOR_CLOUD


def test_ollama_resolution_matches_runtime_precedence() -> None:
    config = JarvisConfig()

    default = resolve_engine_boundary("ollama", config, environ={})
    assert default.boundary is EndpointBoundary.LOCAL_HOST
    assert default.source == "default"

    env = resolve_engine_boundary(
        "ollama",
        config,
        environ={"OLLAMA_HOST": "https://remote.example.test"},
    )
    assert env.boundary is EndpointBoundary.EXTERNAL_NETWORK
    assert env.source == "OLLAMA_HOST"

    config.engine.ollama.host = "http://127.0.0.1:12000"
    configured = resolve_engine_boundary(
        "ollama",
        config,
        environ={"OLLAMA_HOST": "https://remote.example.test"},
    )
    assert configured.boundary is EndpointBoundary.LOCAL_HOST
    assert configured.source == "engine.ollama.host"


def test_compat_config_host_precedes_environment() -> None:
    config = JarvisConfig()
    config.engine.vllm.host = "https://cluster.example.test"

    resolution = resolve_engine_boundary(
        "vllm",
        config,
        environ={"VLLM_HOST": "http://127.0.0.1:8000"},
    )

    assert resolution.boundary is EndpointBoundary.EXTERNAL_NETWORK
    assert resolution.source == "engine.vllm.host"


def test_nim_default_and_custom_endpoint_boundaries() -> None:
    config = JarvisConfig()

    vendor = resolve_engine_boundary("nim", config, environ={})
    assert vendor.boundary is EndpointBoundary.VENDOR_CLOUD
    assert vendor.source == "default"

    repeated_vendor = resolve_engine_boundary(
        "nim",
        config,
        environ={"NIM_HOST": "https://integrate.api.nvidia.com/"},
    )
    assert repeated_vendor.boundary is EndpointBoundary.VENDOR_CLOUD
    assert repeated_vendor.source == "NIM_HOST"

    local = resolve_engine_boundary(
        "nim", config, environ={"NIM_HOST": "http://localhost:8000"}
    )
    assert local.boundary is EndpointBoundary.LOCAL_HOST
    assert local.source == "NIM_HOST"

    remote = resolve_engine_boundary(
        "nim", config, environ={"NIM_HOST": "https://nim.example.test"}
    )
    assert remote.boundary is EndpointBoundary.EXTERNAL_NETWORK
    assert remote.source == "NIM_HOST"


def test_runtime_resolved_engine_is_explicitly_unknown_until_instantiated() -> None:
    resolution = resolve_engine_boundary(
        "vllm-pearl-mining",
        JarvisConfig(),
        environ={},
    )

    assert resolution.boundary is EndpointBoundary.UNKNOWN
    assert resolution.source == "runtime"


def test_unknown_engine_is_not_silently_classified_local() -> None:
    resolution = resolve_engine_boundary("new-engine", JarvisConfig(), environ={})

    assert resolution.boundary is EndpointBoundary.UNKNOWN
    assert resolution.source == "unclassified"
    assert resolution.leaves_local_host is None


def test_instance_boundary_uses_actual_host() -> None:
    local = SimpleNamespace(is_cloud=False, _host="http://localhost:8000")
    remote = SimpleNamespace(is_cloud=False, _host="https://cluster.example.test")
    cloud = SimpleNamespace(is_cloud=True)

    assert boundary_from_engine_instance("vllm", local) is EndpointBoundary.LOCAL_HOST
    assert (
        boundary_from_engine_instance("vllm", remote)
        is EndpointBoundary.EXTERNAL_NETWORK
    )
    assert (
        boundary_from_engine_instance("unregistered-cloud", cloud)
        is EndpointBoundary.VENDOR_CLOUD
    )


def test_nim_instance_default_vendor_endpoint_is_vendor_cloud() -> None:
    nim = SimpleNamespace(
        is_cloud=False,
        _host="https://integrate.api.nvidia.com",
    )

    assert boundary_from_engine_instance("nim", nim) is EndpointBoundary.VENDOR_CLOUD


def test_runtime_resolved_instance_uses_actual_host() -> None:
    engine = SimpleNamespace(
        is_cloud=False,
        _host="https://mining.example.test",
    )

    assert (
        boundary_from_engine_instance("vllm-pearl-mining", engine)
        is EndpointBoundary.EXTERNAL_NETWORK
    )


def test_unknown_instance_without_endpoint_remains_unknown() -> None:
    engine = SimpleNamespace(is_cloud=False)

    assert (
        boundary_from_engine_instance("new-engine", engine) is EndpointBoundary.UNKNOWN
    )


def test_same_host_egress_class_requires_known_boundaries() -> None:
    assert same_host_egress_class(
        EndpointBoundary.IN_PROCESS,
        EndpointBoundary.LOCAL_HOST,
    )
    assert same_host_egress_class(
        EndpointBoundary.EXTERNAL_NETWORK,
        EndpointBoundary.VENDOR_CLOUD,
    )
    assert not same_host_egress_class(
        EndpointBoundary.LOCAL_HOST,
        EndpointBoundary.VENDOR_CLOUD,
    )
    assert not same_host_egress_class(
        EndpointBoundary.UNKNOWN,
        EndpointBoundary.LOCAL_HOST,
    )
