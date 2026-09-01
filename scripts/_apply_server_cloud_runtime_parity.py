from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected one match in {path}, found {count}: {old[:80]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


# serve.py: consume the shared import-safe activation helper instead of keeping
# a private credential list in the CLI module.
replace_once(
    "src/openjarvis/cli/serve.py",
    "from openjarvis.cli._banner import print_banner\nfrom openjarvis.core.config import load_config\n",
    "from openjarvis.cli._banner import print_banner\nfrom openjarvis.core.cloud_activation import active_server_cloud_credentials\nfrom openjarvis.core.config import load_config\n",
)
replace_once(
    "src/openjarvis/cli/serve.py",
    "    import os\n\n    cloud_engine = None\n    _has_cloud = (\n        os.environ.get(\"OPENAI_API_KEY\")\n        or os.environ.get(\"ANTHROPIC_API_KEY\")\n        or os.environ.get(\"GEMINI_API_KEY\")\n        or os.environ.get(\"GOOGLE_API_KEY\")\n        or os.environ.get(\"OPENROUTER_API_KEY\")\n    )\n",
    "    cloud_engine = None\n    _has_cloud = bool(active_server_cloud_credentials())\n",
)

# Scanner imports and credential coverage.
replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    "from openjarvis.core.credentials import TOOL_CREDENTIALS\n",
    "from openjarvis.core.cloud_activation import (\n    SERVER_AUTO_CLOUD_ENGINE_ENV_VARS,\n    active_server_cloud_credentials,\n)\nfrom openjarvis.core.credentials import TOOL_CREDENTIALS\n",
)
replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    '    "CARTESIA_API_KEY": (\n        "Cartesia cloud text-to-speech",\n        {"cartesia", "text_to_speech"},\n    ),\n    "DEEPSEEK_API_KEY": ("DeepSeek cloud inference", {"deepseek"}),\n',
    '    "CARTESIA_API_KEY": (\n        "Cartesia cloud text-to-speech",\n        {"cartesia", "text_to_speech"},\n    ),\n    "DEEPGRAM_API_KEY": ("Deepgram cloud speech-to-text", {"deepgram"}),\n    "DEEPSEEK_API_KEY": ("DeepSeek cloud inference", {"deepseek"}),\n',
)
replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    '    "MINIMAX_API_KEY": ("MiniMax cloud inference", {"minimax"}),\n    "OPENAI_API_KEY": ("OpenAI cloud inference", {"openai", "gpt"}),\n',
    '    "MINIMAX_API_KEY": ("MiniMax cloud inference", {"minimax"}),\n    "NIM_API_KEY": ("NVIDIA NIM API authentication", {"nim"}),\n    "OPENAI_API_KEY": ("OpenAI cloud inference", {"openai", "gpt"}),\n',
)
replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    '("agents-db", "Agent manager database", "agents.db_path", "warn"),',
    '("agents-db", "Agent manager database", "agent_manager.db_path", "warn"),',
)

# Report server auto-activation independently of whether the credential happens
# to match the otherwise configured engine.
replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    "    _audit_environment_credentials(\n        active_config,\n        builder,\n        active_tools=active_tools,\n    )\n",
    "    _audit_server_cloud_engine_activation(builder)\n    _audit_environment_credentials(\n        active_config,\n        builder,\n        active_tools=active_tools,\n    )\n",
)

marker = "\ndef _audit_environment_credentials(\n"
scanner = Path("src/openjarvis/security/data_boundary_audit.py")
text = scanner.read_text(encoding="utf-8")
if text.count(marker) != 1:
    raise RuntimeError("environment credential function marker changed")
server_helpers = '''\n\ndef _server_auto_cloud_envs() -> tuple[str, ...]:\n    """Return redaction-safe names of credentials that activate server cloud routing."""\n\n    return active_server_cloud_credentials()\n\n\ndef _audit_server_cloud_engine_activation(builder: _FindingBuilder) -> None:\n    active = _server_auto_cloud_envs()\n    if not active:\n        return\n    builder.add(\n        finding_id="server-cloud-engine-credential-present",\n        status="warn",\n        title="Server can automatically activate cloud inference from credentials",\n        potential_data_path="process cloud credentials -> jarvis serve -> cloud engine",\n        evidence=(\n            "server cloud auto-activation credential(s) set: "\n            + ", ".join(active)\n            + "; credential values were not emitted"\n        ),\n        recommendation=(\n            "Unset unused server cloud credentials when cloud routing is not intended, "\n            "or run the server in a local-only process environment."\n        ),\n    )\n'''
scanner.write_text(text.replace(marker, server_helpers + marker, 1), encoding="utf-8")

replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    '        active = any(alias in value for alias in aliases for value in active_values)\n        status: Status = "warn" if active else "info"\n',
    '        active = any(alias in value for alias in aliases for value in active_values)\n        server_auto = env_name in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS\n        status: Status = "warn" if active or server_auto else "info"\n',
)

# Treat server auto-activation as a vendor-cloud inference signal for app-level
# memory composition. Only variable names are added to evidence.
replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    '    effective_engine = _first_nonempty(preferred_engine, default_engine, provider)\n    if default_model:\n        boundary, _ = _target_boundary(config, effective_engine, default_model)\n        if boundary is not EndpointBoundary.UNKNOWN:\n            signals.append(("intelligence.default_model", boundary))\n    return signals\n',
    '    effective_engine = _first_nonempty(preferred_engine, default_engine, provider)\n    if default_model:\n        boundary, _ = _target_boundary(config, effective_engine, default_model)\n        if boundary is not EndpointBoundary.UNKNOWN:\n            signals.append(("intelligence.default_model", boundary))\n    for env_name in _server_auto_cloud_envs():\n        signals.append(\n            (f"{env_name} via jarvis serve", EndpointBoundary.VENDOR_CLOUD)\n        )\n    return signals\n',
)

# A web Deep Research request may reuse the active server engine whenever there
# is no explicit deep_research.engine override. If the server can construct a
# cloud engine from credentials, local knowledge therefore has a potential cloud
# route even when engine.default itself is local.
old_knowledge = '''    tools = _configured_tools(config)\n    scan_active = _scan_chunks_surface_active(config, tools)\n    knowledge_exists = _knowledge_store_exists(root)\n    engine, model = _effective_deep_research_target(config)\n    boundary, source = _target_boundary(config, engine, model)\n    outbound = boundary.leaves_local_host is True\n\n    if knowledge_exists and outbound:\n        evidence_parts = [\n            "knowledge.db exists",\n            (\n                "effective deep_research engine = "\n                f"{_quote(engine) if engine else '<empty>'}"\n            ),\n            (\n                "effective deep_research model = "\n                f"{_quote(model) if model else '<empty>'}"\n            ),\n            f"endpoint boundary = {boundary.value} via {source}",\n            "configured endpoint value was not emitted",\n        ]\n'''
new_knowledge = '''    tools = _configured_tools(config)\n    scan_active = _scan_chunks_surface_active(config, tools)\n    knowledge_exists = _knowledge_store_exists(root)\n    explicit_deep_engine = str(_get(config, "deep_research.engine", "") or "").strip()\n    server_cloud_envs = _server_auto_cloud_envs()\n    server_cloud_possible = bool(server_cloud_envs) and not explicit_deep_engine\n    engine, model = _effective_deep_research_target(config)\n    boundary, source = _target_boundary(config, engine, model)\n    outbound = boundary.leaves_local_host is True or server_cloud_possible\n\n    if knowledge_exists and outbound:\n        evidence_parts = [\n            "knowledge.db exists",\n            (\n                "effective deep_research engine = "\n                f"{_quote(engine) if engine else '<empty>'}"\n            ),\n            (\n                "effective deep_research model = "\n                f"{_quote(model) if model else '<empty>'}"\n            ),\n            f"endpoint boundary = {boundary.value} via {source}",\n            "configured endpoint value was not emitted",\n        ]\n        if server_cloud_possible:\n            evidence_parts.append(\n                "jarvis serve cloud auto-activation credential(s) = "\n                + ", ".join(server_cloud_envs)\n                + "; credential values were not emitted"\n            )\n'''
replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    old_knowledge,
    new_knowledge,
)
replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    "        is_vendor = boundary is EndpointBoundary.VENDOR_CLOUD\n",
    "        is_vendor = (\n            boundary is EndpointBoundary.VENDOR_CLOUD or server_cloud_possible\n        )\n",
)

# Make the top-level verdict reflect the newly modeled server cloud surface.
replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    '            "deep-research-cloud-configured",\n        }\n',
    '            "deep-research-cloud-configured",\n            "server-cloud-engine-credential-present",\n        }\n',
)

# Existing expectation was based on scanner-local provider matching and no
# longer reflects the actual server activation behavior.
replace_once(
    "tests/security/test_data_boundary_audit.py",
    '''def test_environment_credentials_report_presence_only(tmp_path, monkeypatch):\n    config = _low_noise_config()\n    monkeypatch.setenv("OPENAI_API_KEY", "secret-key")\n\n    report = build_data_boundary_report(config, tmp_path)\n\n    findings = {finding.id: finding for finding in report.findings}\n    finding = findings["env-credential-openai_api_key"]\n    assert finding.status == "info"\n    assert "OPENAI_API_KEY is set" in finding.evidence\n    assert "secret-key" not in str(report.to_dict(show_paths=True))\n''',
    '''def test_server_cloud_environment_credential_warns_and_redacts(\n    tmp_path, monkeypatch\n):\n    config = _low_noise_config()\n    monkeypatch.setenv("OPENAI_API_KEY", "secret-key")\n\n    report = build_data_boundary_report(config, tmp_path)\n\n    findings = {finding.id: finding for finding in report.findings}\n    assert findings["env-credential-openai_api_key"].status == "warn"\n    assert findings["server-cloud-engine-credential-present"].status == "warn"\n    assert "OPENAI_API_KEY is set" in findings["env-credential-openai_api_key"].evidence\n    assert "secret-key" not in str(report.to_dict(show_paths=True))\n    assert report.verdict == "cloud-capable data boundaries configured"\n''',
)

security_tests = Path("tests/security/test_data_boundary_audit.py")
security_text = security_tests.read_text(encoding="utf-8")
append_marker = "\n\ndef test_server_cloud_key_runtime_parity_regressions"
if append_marker in security_text:
    raise RuntimeError("runtime parity tests already appended")
security_text += '''\n\ndef test_server_cloud_key_runtime_parity_regressions(tmp_path, monkeypatch):\n    config = _low_noise_config()\n    config.agent.context_from_memory = True\n    monkeypatch.setenv("OPENROUTER_API_KEY", "canary-server-cloud-secret")\n\n    report = build_data_boundary_report(config, tmp_path)\n    findings = {finding.id: finding for finding in report.findings}\n\n    assert findings["server-cloud-engine-credential-present"].status == "warn"\n    assert findings["memory-context-to-cloud-risk"].status == "fail"\n    assert report.verdict == "local memory may be sent to cloud inference"\n    assert "canary-server-cloud-secret" not in str(report.to_dict(show_paths=True))\n\n\ndef test_knowledge_can_reach_server_cloud_engine_without_explicit_research_override(\n    tmp_path, monkeypatch\n):\n    config = _low_noise_config()\n    config.engine.default = "ollama"\n    config.deep_research.engine = ""\n    (tmp_path / "knowledge.db").write_text("", encoding="utf-8")\n    monkeypatch.setenv("ANTHROPIC_API_KEY", "canary-knowledge-secret")\n\n    report = build_data_boundary_report(config, tmp_path)\n    findings = {finding.id: finding for finding in report.findings}\n\n    assert findings["knowledge-chunks-to-cloud-risk"].status == "fail"\n    assert "canary-knowledge-secret" not in str(report.to_dict(show_paths=True))\n\n\ndef test_explicit_local_research_engine_blocks_server_cloud_knowledge_path(\n    tmp_path, monkeypatch\n):\n    config = _low_noise_config()\n    config.deep_research.engine = "ollama"\n    (tmp_path / "knowledge.db").write_text("", encoding="utf-8")\n    monkeypatch.setenv("GOOGLE_API_KEY", "canary-explicit-local-secret")\n\n    report = build_data_boundary_report(config, tmp_path)\n    findings = {finding.id: finding for finding in report.findings}\n\n    assert "knowledge-chunks-to-cloud-risk" not in findings\n    assert findings["server-cloud-engine-credential-present"].status == "warn"\n    assert "canary-explicit-local-secret" not in str(report.to_dict(show_paths=True))\n\n\n@pytest.mark.parametrize(\n    ("env_name", "finding_id"),\n    [\n        ("DEEPGRAM_API_KEY", "env-credential-deepgram_api_key"),\n        ("NIM_API_KEY", "env-credential-nim_api_key"),\n    ],\n)\ndef test_specialized_runtime_credentials_are_redacted(\n    tmp_path, monkeypatch, env_name, finding_id\n):\n    config = _low_noise_config()\n    secret = f"canary-{env_name.lower()}"\n    monkeypatch.setenv(env_name, secret)\n\n    report = build_data_boundary_report(config, tmp_path)\n    findings = {finding.id: finding for finding in report.findings}\n\n    assert finding_id in findings\n    assert secret not in str(report.to_dict(show_paths=True))\n\n\ndef test_custom_agent_manager_db_path_is_audited(tmp_path):\n    config = _low_noise_config()\n    custom = tmp_path / "state" / "custom-agents.sqlite"\n    custom.parent.mkdir()\n    custom.write_text("", encoding="utf-8")\n    config.agent_manager.db_path = str(custom)\n\n    report = build_data_boundary_report(config, tmp_path)\n    findings = {finding.id: finding for finding in report.findings}\n\n    assert findings["local-store-agents-db"].status == "warn"\n    assert findings["local-store-agents-db"].absolute_location == str(custom)\n\n\ndef test_config_store_paths_resolve_against_jarvis_config():\n    from openjarvis.security.data_boundary_audit import _CONFIG_STORE_PATHS, _get\n\n    config = JarvisConfig()\n    missing = object()\n    for _finding_id, _title, dotted_path, _status in _CONFIG_STORE_PATHS:\n        assert _get(config, dotted_path, missing) is not missing, dotted_path\n'''
security_tests.write_text(security_text, encoding="utf-8")

# Dedicated import-safe helper tests keep the server/scanner credential set from
# drifting independently again.
Path("tests/core/test_cloud_activation.py").write_text(
    '''from __future__ import annotations\n\nfrom openjarvis.core.cloud_activation import (\n    SERVER_AUTO_CLOUD_ENGINE_ENV_VARS,\n    active_server_cloud_credentials,\n)\n\n\ndef test_server_cloud_activation_credential_set_is_exact():\n    assert SERVER_AUTO_CLOUD_ENGINE_ENV_VARS == {\n        "ANTHROPIC_API_KEY",\n        "GEMINI_API_KEY",\n        "GOOGLE_API_KEY",\n        "OPENAI_API_KEY",\n        "OPENROUTER_API_KEY",\n    }\n\n\ndef test_active_server_cloud_credentials_returns_names_only():\n    environ = {\n        "OPENROUTER_API_KEY": "canary-secret-value",\n        "GOOGLE_API_KEY": "",\n        "UNRELATED": "value",\n    }\n\n    active = active_server_cloud_credentials(environ)\n\n    assert active == ("OPENROUTER_API_KEY",)\n    assert "canary-secret-value" not in repr(active)\n''',
    encoding="utf-8",
)

# Documentation: state the runtime composition explicitly and preserve the
# scanner's non-observation scope.
replace_once(
    "docs/user-guide/data-boundary-scan.md",
    "- cloud-capable model provider, engine, and default model settings\n",
    "- cloud-capable model provider, engine, and default model settings\n- server cloud-engine auto-activation from supported credential environment variables\n",
)
replace_once(
    "docs/user-guide/data-boundary-scan.md",
    "- API-key and other runtime credential environment variables (presence only)\n",
    "- API-key and other runtime credential environment variables (presence only, including Deepgram and NIM)\n",
)
replace_once(
    "docs/user-guide/data-boundary-scan.md",
    "Static Deep Research targeting uses configuration only (no request overrides):\n`deep_research.engine` or `engine.default`, and `deep_research.model` or\n`server.model` or `intelligence.default_model`.\n",
    "Static Deep Research targeting uses configuration only (no request overrides):\n`deep_research.engine` or `engine.default`, and `deep_research.model` or\n`server.model` or `intelligence.default_model`. When no explicit\n`deep_research.engine` is set, server cloud auto-activation credentials are also\nreported as a potential cloud route because the web research path may reuse the\nactive server engine.\n",
)
