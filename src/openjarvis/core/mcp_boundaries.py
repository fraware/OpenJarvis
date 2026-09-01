"""Import-safe MCP transport and trust-boundary metadata.

The helpers in this module are deliberately side-effect free. They inspect only
already-loaded configuration values: they do not open referenced config files,
start subprocesses, connect to MCP servers, or return endpoint/credential
values. Runtime transport selection and static security diagnostics can
therefore share the same URL-before-command precedence without importing the
MCP runtime stack.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from openjarvis.core.inference_boundaries import EndpointBoundary, classify_endpoint


class MCPTransportKind(str, Enum):
    """Transport selected for one MCP server configuration."""

    STREAMABLE_HTTP = "streamable-http"
    STDIO = "stdio"
    INVALID = "invalid"


class MCPConfigSource(str, Enum):
    """How ``tools.mcp.servers`` can be inspected without filesystem I/O."""

    EMPTY = "empty"
    INLINE = "inline"
    FILE_REFERENCE = "file-reference"
    INVALID_INLINE = "invalid-inline"


@dataclass(frozen=True, slots=True)
class MCPServerBoundary:
    """Redaction-safe boundary classification for one inline MCP server."""

    transport: MCPTransportKind
    endpoint_boundary: EndpointBoundary = EndpointBoundary.UNKNOWN


@dataclass(frozen=True, slots=True)
class MCPConfigInspection:
    """Redaction-safe inspection of the configured MCP server declaration."""

    source: MCPConfigSource
    servers: tuple[MCPServerBoundary, ...] = ()


def mcp_transport_kind(server_config: Mapping[str, Any]) -> MCPTransportKind:
    """Return the runtime transport choice using URL-before-command precedence."""

    if server_config.get("url"):
        return MCPTransportKind.STREAMABLE_HTTP
    if server_config.get("command"):
        return MCPTransportKind.STDIO
    return MCPTransportKind.INVALID


def mcp_server_boundary(server_config: Mapping[str, Any]) -> MCPServerBoundary:
    """Classify one server without returning endpoint, token, or command values."""

    transport = mcp_transport_kind(server_config)
    if transport is MCPTransportKind.STREAMABLE_HTTP:
        return MCPServerBoundary(
            transport=transport,
            endpoint_boundary=classify_endpoint(server_config.get("url")),
        )
    return MCPServerBoundary(transport=transport)


def _normalize_inline_servers(value: Any) -> list[Mapping[str, Any]] | None:
    """Mirror runtime inline MCP shape validation without reading any files."""

    if isinstance(value, Mapping):
        entries: list[Any] = [value]
    elif isinstance(value, list):
        entries = value
    else:
        return None

    normalized: list[Mapping[str, Any]] = []
    for entry in entries:
        candidate = entry
        if isinstance(candidate, str):
            try:
                candidate = json.loads(candidate)
            except (json.JSONDecodeError, TypeError):
                return None
        if not isinstance(candidate, Mapping):
            return None
        normalized.append(candidate)
    return normalized


def inspect_mcp_servers(raw: Any) -> MCPConfigInspection:
    """Inspect MCP server config without resolving file references.

    Inline JSON is parsed because its bytes are already part of the loaded
    configuration. A non-inline value is classified only as a file reference;
    this function never opens it. Invalid inline JSON is reported as such with
    no partial server classification, matching runtime all-or-nothing shape
    validation.
    """

    text = str(raw or "").strip()
    if not text:
        return MCPConfigInspection(MCPConfigSource.EMPTY)
    if text[0] not in "[{":
        return MCPConfigInspection(MCPConfigSource.FILE_REFERENCE)

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return MCPConfigInspection(MCPConfigSource.INVALID_INLINE)

    servers = _normalize_inline_servers(parsed)
    if servers is None:
        return MCPConfigInspection(MCPConfigSource.INVALID_INLINE)

    return MCPConfigInspection(
        source=MCPConfigSource.INLINE,
        servers=tuple(mcp_server_boundary(server) for server in servers),
    )


__all__ = [
    "MCPConfigInspection",
    "MCPConfigSource",
    "MCPServerBoundary",
    "MCPTransportKind",
    "inspect_mcp_servers",
    "mcp_server_boundary",
    "mcp_transport_kind",
]
