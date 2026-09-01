"""Tests for import-safe MCP boundary metadata."""

from __future__ import annotations

from openjarvis.core.inference_boundaries import EndpointBoundary
from openjarvis.core.mcp_boundaries import (
    MCPConfigSource,
    MCPTransportKind,
    inspect_mcp_servers,
    mcp_server_boundary,
    mcp_transport_kind,
)


def test_url_takes_precedence_over_command() -> None:
    config = {
        "url": "http://localhost:8123/mcp",
        "command": "canary-command",
        "args": ["canary-arg"],
    }

    assert mcp_transport_kind(config) is MCPTransportKind.STREAMABLE_HTTP


def test_stdio_selected_when_command_is_present_without_url() -> None:
    assert mcp_transport_kind({"command": "canary-command"}) is MCPTransportKind.STDIO


def test_missing_url_and_command_is_invalid() -> None:
    assert mcp_transport_kind({"name": "empty"}) is MCPTransportKind.INVALID


def test_http_boundary_distinguishes_loopback_from_external_network() -> None:
    local = mcp_server_boundary({"url": "http://127.0.0.1:8123/mcp"})
    external = mcp_server_boundary({"url": "https://example.invalid/mcp"})

    assert local.transport is MCPTransportKind.STREAMABLE_HTTP
    assert local.endpoint_boundary is EndpointBoundary.LOCAL_HOST
    assert external.transport is MCPTransportKind.STREAMABLE_HTTP
    assert external.endpoint_boundary is EndpointBoundary.EXTERNAL_NETWORK


def test_unspecified_http_host_remains_unknown() -> None:
    boundary = mcp_server_boundary({"url": "http://0.0.0.0:8123/mcp"})

    assert boundary.transport is MCPTransportKind.STREAMABLE_HTTP
    assert boundary.endpoint_boundary is EndpointBoundary.UNKNOWN


def test_inspect_inline_servers_classifies_without_exposing_values() -> None:
    raw = """[
        {"name":"remote-canary","url":"https://secret.example/mcp","token":"secret-token"},
        {"name":"local-canary","url":"http://localhost:8123/mcp"},
        {"name":"process-canary","command":"secret-command","args":["secret-arg"]},
        {"name":"invalid-canary"}
    ]"""

    inspection = inspect_mcp_servers(raw)

    assert inspection.source is MCPConfigSource.INLINE
    assert [server.transport for server in inspection.servers] == [
        MCPTransportKind.STREAMABLE_HTTP,
        MCPTransportKind.STREAMABLE_HTTP,
        MCPTransportKind.STDIO,
        MCPTransportKind.INVALID,
    ]
    assert [server.endpoint_boundary for server in inspection.servers] == [
        EndpointBoundary.EXTERNAL_NETWORK,
        EndpointBoundary.LOCAL_HOST,
        EndpointBoundary.UNKNOWN,
        EndpointBoundary.UNKNOWN,
    ]
    rendered = repr(inspection)
    for secret in (
        "secret.example",
        "secret-token",
        "secret-command",
        "secret-arg",
        "remote-canary",
    ):
        assert secret not in rendered


def test_single_inline_object_is_normalized() -> None:
    inspection = inspect_mcp_servers(
        '{"name":"one","url":"http://localhost:8123/mcp"}'
    )

    assert inspection.source is MCPConfigSource.INLINE
    assert len(inspection.servers) == 1
    assert inspection.servers[0].endpoint_boundary is EndpointBoundary.LOCAL_HOST


def test_legacy_json_string_entry_is_normalized() -> None:
    raw = '["{\\"name\\":\\"legacy\\",\\"command\\":\\"runner\\"}"]'

    inspection = inspect_mcp_servers(raw)

    assert inspection.source is MCPConfigSource.INLINE
    assert len(inspection.servers) == 1
    assert inspection.servers[0].transport is MCPTransportKind.STDIO


def test_invalid_inline_shape_is_all_or_nothing() -> None:
    inspection = inspect_mcp_servers('[{"url":"https://example.invalid"}, 1]')

    assert inspection.source is MCPConfigSource.INVALID_INLINE
    assert inspection.servers == ()


def test_malformed_inline_json_is_invalid() -> None:
    inspection = inspect_mcp_servers('[{"url":]')

    assert inspection.source is MCPConfigSource.INVALID_INLINE
    assert inspection.servers == ()


def test_file_reference_is_classified_without_reading_it(tmp_path) -> None:
    referenced = tmp_path / "mcp-servers.json"
    referenced.write_text(
        '[{"url":"https://secret.example/mcp","token":"secret-token"}]',
        encoding="utf-8",
    )

    inspection = inspect_mcp_servers(str(referenced))

    assert inspection.source is MCPConfigSource.FILE_REFERENCE
    assert inspection.servers == ()
    assert "secret.example" not in repr(inspection)
    assert "secret-token" not in repr(inspection)


def test_empty_mcp_config_is_empty() -> None:
    assert inspect_mcp_servers("   ").source is MCPConfigSource.EMPTY
