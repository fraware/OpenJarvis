from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one match, found {count}")
    file.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    "        inspection = inspect_mcp_servers(mcp_servers)\n        if inspection.source is MCPConfigSource.FILE_REFERENCE:\n",
    "        inspection = inspect_mcp_servers(mcp_servers)\n        if inspection.source is MCPConfigSource.INLINE and not inspection.servers:\n            return\n        if inspection.source is MCPConfigSource.FILE_REFERENCE:\n",
)

replace_once(
    "src/openjarvis/mcp/loader.py",
    "    ``allowed_names`` is an outer filter applied after each server's\n    own include/exclude filter. Pass the caller's `--tools`/`enabled`\n    list to honour CLI scoping; pass ``None`` to take every tool.\n\n",
    "    ``allowed_names`` is an outer filter applied after each server's\n    own include/exclude filter. Pass the caller's `--tools`/`enabled`\n    list to honour CLI scoping; pass ``None`` to take every tool.\n\n    ``config_dir`` enables the same inline-JSON-or-file resolution used by\n    the main system builder. Callers loading a JarvisConfig should pass its\n    recorded source directory so relative MCP config references resolve from\n    the configuration file rather than the process working directory.\n\n",
)

security_tests = Path("tests/security/test_data_boundary_audit.py")
text = security_tests.read_text(encoding="utf-8")
anchor = "\n\ndef test_mcp_inline_transports_are_classified_without_values(tmp_path):\n"
if text.count(anchor) != 1:
    raise RuntimeError("MCP scanner test anchor drifted")
insert = '''\n\ndef test_empty_inline_mcp_server_list_has_no_surface_finding(tmp_path):\n    config = _low_noise_config()\n    config.tools.mcp.enabled = True\n    config.tools.mcp.servers = "[]"\n\n    report = build_data_boundary_report(config, tmp_path)\n\n    assert "mcp-servers-configured" not in {item.id for item in report.findings}\n'''
security_tests.write_text(text.replace(anchor, insert + anchor), encoding="utf-8")

replace_once(
    "docs/user-guide/data-boundary-scan.md",
    "Configured database paths (for example `traces.db_path` or `memory.db_path`)\nare resolved from config when set, not only the default locations under the\nOpenJarvis home directory.\n\n",
    "Configured database paths (for example `traces.db_path` or `memory.db_path`)\nare resolved from config when set, not only the default locations under the\nOpenJarvis home directory.\n\nFor inline MCP server configuration, the scan classifies configured transports\nas local-host HTTP, external-network HTTP, unresolved HTTP, stdio subprocess, or\ninvalid without emitting server names, endpoints, tokens, commands, or arguments.\nIf `tools.mcp.servers` references a JSON file, the scan reports the reference as\nunresolved and deliberately does not open that file; runtime paths may resolve it\nwhen they actually construct MCP clients. An inline empty array creates no MCP\nserver-surface finding.\n\n",
)

print("refined MCP boundary diagnostics")
