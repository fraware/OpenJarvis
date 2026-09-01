from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one match, found {count}")
    file.write_text(text.replace(old, new, 1), encoding="utf-8")


# Shared loader: preserve lazy runtime imports, add file-backed config parity,
# and centralize URL-before-command transport selection.
replace_once(
    "src/openjarvis/mcp/loader.py",
    "import json\nimport logging\nfrom typing import TYPE_CHECKING, Any, Optional\n",
    "import json\nimport logging\nfrom pathlib import Path\nfrom typing import TYPE_CHECKING, Any, Optional\n",
)
replace_once(
    "src/openjarvis/mcp/loader.py",
    "def load_mcp_tools_from_config(\n    mcp_cfg: Any,\n    *,\n    allowed_names: Optional[set[str]] = None,\n) -> tuple[list[\"BaseTool\"], list[\"MCPClient\"]]:",
    "def load_mcp_tools_from_config(\n    mcp_cfg: Any,\n    *,\n    allowed_names: Optional[set[str]] = None,\n    config_dir: Path | None = None,\n) -> tuple[list[\"BaseTool\"], list[\"MCPClient\"]]:",
)
replace_once(
    "src/openjarvis/mcp/loader.py",
    "    try:\n        server_list = (\n            json.loads(servers_blob) if isinstance(servers_blob, str) else servers_blob\n        )\n    except (json.JSONDecodeError, TypeError) as exc:\n        logger.warning(\"Failed to parse MCP servers config: %s\", exc)\n        return [], []\n",
    "    try:\n        if isinstance(servers_blob, str) and config_dir is not None:\n            from openjarvis.core.config import resolve_mcp_servers\n\n            server_list = resolve_mcp_servers(servers_blob, Path(config_dir))\n        else:\n            server_list = (\n                json.loads(servers_blob)\n                if isinstance(servers_blob, str)\n                else servers_blob\n            )\n    except (json.JSONDecodeError, OSError, UnicodeError, ValueError, TypeError) as exc:\n        logger.warning(\"Failed to parse MCP servers config: %s\", exc)\n        return [], []\n",
)
replace_once(
    "src/openjarvis/mcp/loader.py",
    "    from openjarvis.mcp.client import MCPClient\n    from openjarvis.mcp.transport import StdioTransport, StreamableHTTPTransport\n    from openjarvis.tools.mcp_adapter import MCPToolProvider\n",
    "    from openjarvis.core.mcp_boundaries import MCPTransportKind, mcp_transport_kind\n    from openjarvis.mcp.client import MCPClient\n    from openjarvis.mcp.transport import StdioTransport, StreamableHTTPTransport\n    from openjarvis.tools.mcp_adapter import MCPToolProvider\n",
)
replace_once(
    "src/openjarvis/mcp/loader.py",
    "            if url:\n                transport = StreamableHTTPTransport(url=url, token=token)\n            elif command:\n                transport = StdioTransport(command=[command] + args)\n            else:\n",
    "            transport_kind = mcp_transport_kind(cfg)\n            if transport_kind is MCPTransportKind.STREAMABLE_HTTP:\n                transport = StreamableHTTPTransport(url=url, token=token)\n            elif transport_kind is MCPTransportKind.STDIO:\n                transport = StdioTransport(command=[command] + args)\n            else:\n",
)

# CLI entry points know the loaded config directory, so file-backed MCP config
# now resolves consistently with SystemBuilder and the managed-agent server.
replace_once(
    "src/openjarvis/cli/serve.py",
    "        managed_mcp_tools, mcp_clients = load_mcp_tools_from_config(config.tools.mcp)\n",
    "        managed_mcp_tools, mcp_clients = load_mcp_tools_from_config(\n            config.tools.mcp,\n            config_dir=config._config_dir,\n        )\n",
)
replace_once(
    "src/openjarvis/cli/ask.py",
    "    mcp_tools, mcp_clients = load_mcp_tools_from_config(\n        config.tools.mcp,\n        allowed_names=set(tool_names) if tool_names else None,\n    )\n",
    "    mcp_tools, mcp_clients = load_mcp_tools_from_config(\n        config.tools.mcp,\n        allowed_names=set(tool_names) if tool_names else None,\n        config_dir=config._config_dir,\n    )\n",
)

# SystemBuilder and managed-agent discovery use the same pure transport choice.
replace_once(
    "src/openjarvis/system/builder.py",
    "        from openjarvis.mcp.client import MCPClient\n        from openjarvis.mcp.transport import StdioTransport, StreamableHTTPTransport\n        from openjarvis.tools.mcp_adapter import MCPToolProvider\n",
    "        from openjarvis.core.mcp_boundaries import (\n            MCPTransportKind,\n            mcp_transport_kind,\n        )\n        from openjarvis.mcp.client import MCPClient\n        from openjarvis.mcp.transport import StdioTransport, StreamableHTTPTransport\n        from openjarvis.tools.mcp_adapter import MCPToolProvider\n",
)
replace_once(
    "src/openjarvis/system/builder.py",
    "        if url:\n            transport = StreamableHTTPTransport(url=url, token=token)\n        elif command:\n            transport = StdioTransport(command=[command] + args)\n        else:\n",
    "        transport_kind = mcp_transport_kind(cfg)\n        if transport_kind is MCPTransportKind.STREAMABLE_HTTP:\n            transport = StreamableHTTPTransport(url=url, token=token)\n        elif transport_kind is MCPTransportKind.STDIO:\n            transport = StdioTransport(command=[command] + args)\n        else:\n",
)
replace_once(
    "src/openjarvis/server/agent_manager_routes.py",
    "    from openjarvis.mcp.client import MCPClient\n    from openjarvis.mcp.transport import StdioTransport, StreamableHTTPTransport\n    from openjarvis.tools.mcp_adapter import MCPToolProvider\n",
    "    from openjarvis.core.mcp_boundaries import MCPTransportKind, mcp_transport_kind\n    from openjarvis.mcp.client import MCPClient\n    from openjarvis.mcp.transport import StdioTransport, StreamableHTTPTransport\n    from openjarvis.tools.mcp_adapter import MCPToolProvider\n",
)
replace_once(
    "src/openjarvis/server/agent_manager_routes.py",
    "            if url:\n                transport = StreamableHTTPTransport(url=url, token=token)\n            elif command:\n                transport = StdioTransport(command=[command] + args)\n            else:\n",
    "            transport_kind = mcp_transport_kind(cfg)\n            if transport_kind is MCPTransportKind.STREAMABLE_HTTP:\n                transport = StreamableHTTPTransport(url=url, token=token)\n            elif transport_kind is MCPTransportKind.STDIO:\n                transport = StdioTransport(command=[command] + args)\n            else:\n",
)

# Scanner: classify already-loaded inline MCP config, but never resolve/read a
# referenced JSON file and never emit endpoint/token/command/server-name values.
replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    "from openjarvis.core.inference_boundaries import (\n    EndpointBoundary,\n    resolve_engine_boundary,\n)\n",
    "from openjarvis.core.inference_boundaries import (\n    EndpointBoundary,\n    resolve_engine_boundary,\n)\nfrom openjarvis.core.mcp_boundaries import (\n    MCPConfigSource,\n    MCPTransportKind,\n    inspect_mcp_servers,\n)\n",
)
replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    "    mcp_enabled = bool(_get(config, \"tools.mcp.enabled\", False))\n    mcp_servers = str(_get(config, \"tools.mcp.servers\", \"\") or \"\").strip()\n    if mcp_enabled and mcp_servers:\n        builder.add(\n            finding_id=\"mcp-servers-configured\",\n            status=\"warn\",\n            title=\"External MCP servers are configured\",\n            potential_data_path=\"agent tool calls/context -> configured MCP servers\",\n            evidence=\"tools.mcp.enabled = true; tools.mcp.servers is non-empty\",\n            recommendation=(\n                \"Review MCP server trust, transport, and tool schemas before sending \"\n                \"sensitive prompts or tool arguments.\"\n            ),\n        )\n",
    "    mcp_enabled = bool(_get(config, \"tools.mcp.enabled\", False))\n    mcp_servers = str(_get(config, \"tools.mcp.servers\", \"\") or \"\").strip()\n    if mcp_enabled and mcp_servers:\n        inspection = inspect_mcp_servers(mcp_servers)\n        if inspection.source is MCPConfigSource.FILE_REFERENCE:\n            evidence = (\n                \"tools.mcp.enabled = true; tools.mcp.servers is a file reference; \"\n                \"referenced file contents were not read\"\n            )\n            potential_data_path = (\n                \"agent tool calls/context -> unresolved configured MCP transports\"\n            )\n        elif inspection.source is MCPConfigSource.INVALID_INLINE:\n            evidence = (\n                \"tools.mcp.enabled = true; inline MCP server config is invalid; \"\n                \"raw config value was not emitted\"\n            )\n            potential_data_path = (\n                \"agent tool calls/context -> unresolved configured MCP transports\"\n            )\n        else:\n            local_http = sum(\n                server.transport is MCPTransportKind.STREAMABLE_HTTP\n                and server.endpoint_boundary is EndpointBoundary.LOCAL_HOST\n                for server in inspection.servers\n            )\n            external_http = sum(\n                server.transport is MCPTransportKind.STREAMABLE_HTTP\n                and server.endpoint_boundary is EndpointBoundary.EXTERNAL_NETWORK\n                for server in inspection.servers\n            )\n            unknown_http = sum(\n                server.transport is MCPTransportKind.STREAMABLE_HTTP\n                and server.endpoint_boundary is EndpointBoundary.UNKNOWN\n                for server in inspection.servers\n            )\n            stdio = sum(\n                server.transport is MCPTransportKind.STDIO\n                for server in inspection.servers\n            )\n            invalid = sum(\n                server.transport is MCPTransportKind.INVALID\n                for server in inspection.servers\n            )\n            evidence = (\n                \"tools.mcp.enabled = true; inline transport classes: \"\n                f\"external-http={external_http}, local-http={local_http}, \"\n                f\"unknown-http={unknown_http}, stdio={stdio}, invalid={invalid}; \"\n                \"endpoint, token, command, argument, and server-name values were \"\n                \"not emitted\"\n            )\n            potential_data_path = (\n                \"agent tool calls/context -> configured MCP HTTP/subprocess transports\"\n            )\n        builder.add(\n            finding_id=\"mcp-servers-configured\",\n            status=\"warn\",\n            title=\"MCP server transports are configured\",\n            potential_data_path=potential_data_path,\n            evidence=evidence,\n            recommendation=(\n                \"Review MCP server trust, transport, and tool schemas before sending \"\n                \"sensitive prompts or tool arguments. Treat stdio as a subprocess \"\n                \"boundary and non-local HTTP as a network boundary.\"\n            ),\n        )\n",
)

# Regression tests for runtime file-backed config and precedence.
loader_tests = Path("tests/mcp/test_loader.py")
loader_text = loader_tests.read_text(encoding="utf-8")
anchor = "\n\nclass TestLoaderTokenPlumbing:\n"
if loader_text.count(anchor) != 1:
    raise RuntimeError("tests/mcp/test_loader.py: token plumbing anchor drifted")
loader_insert = r'''

class TestLoaderConfigResolution:
    def test_file_backed_config_resolves_from_config_dir(
        self, _mock_mcp_stack, tmp_path
    ):
        from openjarvis.mcp.loader import load_mcp_tools_from_config

        servers_file = tmp_path / "mcp-servers.json"
        servers_file.write_text(
            '[{"name":"file-backed","url":"http://localhost:9583/mcp"}]',
            encoding="utf-8",
        )
        cfg = _make_mcp_cfg(enabled=True, servers="mcp-servers.json")

        load_mcp_tools_from_config(cfg, config_dir=tmp_path)

        _mock_mcp_stack["http"].assert_called_once_with(
            url="http://localhost:9583/mcp",
            token=None,
        )

    def test_url_wins_over_command_in_runtime_loader(self, _mock_mcp_stack):
        from openjarvis.mcp.loader import load_mcp_tools_from_config

        cfg = _make_mcp_cfg(
            enabled=True,
            servers=[
                {
                    "url": "http://localhost:9583/mcp",
                    "command": "must-not-run",
                    "args": ["must-not-run-either"],
                }
            ],
        )

        load_mcp_tools_from_config(cfg)

        _mock_mcp_stack["http"].assert_called_once()
        _mock_mcp_stack["stdio"].assert_not_called()
'''
loader_tests.write_text(loader_text.replace(anchor, loader_insert + anchor), encoding="utf-8")

# Scanner redaction/classification tests.
security_tests = Path("tests/security/test_data_boundary_audit.py")
security_text = security_tests.read_text(encoding="utf-8")
anchor = "\n\ndef test_image_generate_produces_outbound_warn(tmp_path):\n"
if security_text.count(anchor) != 1:
    raise RuntimeError("tests/security/test_data_boundary_audit.py: MCP test anchor drifted")
security_insert = r'''


def test_mcp_inline_transports_are_classified_without_values(tmp_path):
    config = _low_noise_config()
    config.tools.mcp.enabled = True
    config.tools.mcp.servers = (
        '[{"name":"remote-canary","url":"https://secret.example/mcp",'
        '"token":"secret-token"},'
        '{"name":"local-canary","url":"http://localhost:9583/mcp"},'
        '{"name":"process-canary","command":"secret-command",'
        '"args":["secret-arg"]},'
        '{"name":"invalid-canary"}]'
    )

    report = build_data_boundary_report(config, tmp_path)
    payload = str(report.to_dict(show_paths=True))
    finding = {item.id: item for item in report.findings}["mcp-servers-configured"]

    assert finding.status == "warn"
    assert "external-http=1" in finding.evidence
    assert "local-http=1" in finding.evidence
    assert "stdio=1" in finding.evidence
    assert "invalid=1" in finding.evidence
    for secret in (
        "secret.example",
        "secret-token",
        "secret-command",
        "secret-arg",
        "remote-canary",
        "local-canary",
        "process-canary",
    ):
        assert secret not in payload


def test_mcp_url_precedence_is_reflected_in_scanner(tmp_path):
    config = _low_noise_config()
    config.tools.mcp.enabled = True
    config.tools.mcp.servers = (
        '[{"url":"http://localhost:9583/mcp","command":"must-not-run"}]'
    )

    report = build_data_boundary_report(config, tmp_path)
    finding = {item.id: item for item in report.findings}["mcp-servers-configured"]

    assert "local-http=1" in finding.evidence
    assert "stdio=0" in finding.evidence
    assert "must-not-run" not in str(report.to_dict(show_paths=True))


def test_mcp_file_reference_is_not_opened_by_scanner(tmp_path):
    config = _low_noise_config()
    config.tools.mcp.enabled = True
    referenced = tmp_path / "private-mcp-canary.json"
    referenced.write_text(
        '[{"url":"https://secret.example/mcp","token":"secret-token"}]',
        encoding="utf-8",
    )
    config.tools.mcp.servers = str(referenced)

    report = build_data_boundary_report(config, tmp_path)
    payload = str(report.to_dict(show_paths=True))
    finding = {item.id: item for item in report.findings}["mcp-servers-configured"]

    assert "file reference" in finding.evidence
    assert "were not read" in finding.evidence
    assert "secret.example" not in payload
    assert "secret-token" not in payload
    assert "private-mcp-canary.json" not in payload


def test_mcp_invalid_inline_config_is_reported_without_raw_value(tmp_path):
    config = _low_noise_config()
    config.tools.mcp.enabled = True
    config.tools.mcp.servers = '[{"url":"https://secret.example", 1]'

    report = build_data_boundary_report(config, tmp_path)
    payload = str(report.to_dict(show_paths=True))
    finding = {item.id: item for item in report.findings}["mcp-servers-configured"]

    assert "inline MCP server config is invalid" in finding.evidence
    assert "secret.example" not in payload
'''
security_tests.write_text(
    security_text.replace(anchor, security_insert + anchor), encoding="utf-8"
)

print("patched MCP boundary parity")
