"""Polish runtime-parity changes before rebuilding the clean branch.

Temporary branch-local helper. Removed before opening the upstream PR.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "src/openjarvis/security/data_boundary_audit.py"
CLI_TEST = ROOT / "tests/cli/test_scan_runtime_parity.py"
SECURITY_TEST = ROOT / "tests/security/test_data_boundary_runtime_parity.py"
OLD_HELPER = ROOT / "src/openjarvis/engine/cloud_activation.py"
OLD_TEST = ROOT / "tests/engine/test_cloud_activation.py"
CORE_TEST = ROOT / "tests/core/test_cloud_activation.py"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def replace_region(
    text: str,
    start_marker: str,
    end_marker: str | None,
    replacement: str,
    label: str,
) -> str:
    start = text.find(start_marker)
    if start < 0:
        raise RuntimeError(f"{label}: start marker not found")
    if end_marker is None:
        end = len(text)
    else:
        end = text.find(end_marker, start + len(start_marker))
        if end < 0:
            raise RuntimeError(f"{label}: end marker not found")
    return text[:start] + replacement.rstrip() + "\n\n" + text[end:].lstrip("\n")


def patch_scanner() -> None:
    text = SCANNER.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "def _nim_uses_default_vendor_host(engine: Any) -> bool:\n"
        "    return _is_nim_engine_value(engine) and not bool(os.environ.get(\"NIM_HOST\"))\n\n\n"
        "def _nim_uses_custom_host(engine: Any) -> bool:\n"
        "    return _is_nim_engine_value(engine) and bool(os.environ.get(\"NIM_HOST\"))\n",
        "def _nim_host_override_present() -> bool:\n"
        "    \"\"\"Return whether NIM_HOST exists without inspecting its value.\"\"\"\n"
        "    return \"NIM_HOST\" in os.environ\n\n\n"
        "def _nim_uses_default_vendor_host(engine: Any) -> bool:\n"
        "    return _is_nim_engine_value(engine) and not _nim_host_override_present()\n\n\n"
        "def _nim_uses_custom_host(engine: Any) -> bool:\n"
        "    return _is_nim_engine_value(engine) and _nim_host_override_present()\n",
        "NIM host presence semantics",
    )
    text = replace_once(
        text,
        "    if os.environ.get(\"NIM_HOST\"):\n",
        "    if _nim_host_override_present():\n",
        "NIM audit host presence semantics",
    )
    text = replace_once(
        text,
        "        active = env_name in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS or any(\n"
        "            alias in value for alias in aliases for value in active_values\n"
        "        )\n",
        "        active = any(\n"
        "            alias in value for alias in aliases for value in active_values\n"
        "        )\n",
        "separate credential presence from server activation",
    )
    text = replace_once(
        text,
        "    Presence is sufficient because ``jarvis serve`` uses the same condition to\n"
        "    construct a cloud engine. Credential values are never emitted.\n",
        "    A non-empty value is sufficient because ``jarvis serve`` uses the same\n"
        "    truthiness check. Credential values are never emitted.\n",
        "activation helper wording",
    )
    compile(text, str(SCANNER), "exec")
    SCANNER.write_text(text, encoding="utf-8")


def patch_cli_test() -> None:
    text = CLI_TEST.read_text(encoding="utf-8")
    if "import json\n" not in text:
        text = replace_once(
            text,
            "from __future__ import annotations\n\n",
            "from __future__ import annotations\n\nimport json\n\n",
            "CLI JSON import",
        )
    replacement = '''def test_strict_mode_fails_when_server_cloud_engine_can_auto_activate(
    monkeypatch, tmp_path
):
    for env_name in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS:
        monkeypatch.delenv(env_name, raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "canary-provider-secret")

    config = _low_noise_config()
    monkeypatch.setattr(
        "openjarvis.cli.scan_cmd._load_data_boundary_config",
        lambda: (config, tmp_path, True, "", ""),
    )
    monkeypatch.setattr("openjarvis.cli.scan_cmd.get_config_dir", lambda: tmp_path)

    result = CliRunner().invoke(
        scan,
        ["--data-boundaries", "--strict", "--json"],
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    findings = {finding["id"]: finding for finding in payload["findings"]}
    assert findings["server-cloud-engine-credential-present"]["status"] == "warn"
    assert "canary-provider-secret" not in result.output
'''
    text = replace_region(
        text,
        "def test_strict_mode_fails_when_server_cloud_engine_can_auto_activate(",
        None,
        replacement,
        "CLI strict-mode regression",
    )
    compile(text, str(CLI_TEST), "exec")
    CLI_TEST.write_text(text, encoding="utf-8")


def patch_security_test() -> None:
    text = SECURITY_TEST.read_text(encoding="utf-8")

    first = '''def test_server_auto_cloud_credential_is_warn_without_cloud_config(
    tmp_path, monkeypatch
):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "canary-provider-secret")

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["server-cloud-engine-credential-present"].status == "warn"
    assert findings["env-credential-anthropic_api_key"].status == "info"
    rendered = str(report.to_dict(show_paths=True))
    assert "canary-provider-secret" not in rendered
    assert report.verdict == "cloud-capable data boundaries configured"
'''
    text = replace_region(
        text,
        "def test_server_auto_cloud_credential_is_warn_without_cloud_config(",
        "def test_memory_plus_server_auto_cloud_credential_is_fail(",
        first,
        "server activation finding",
    )

    second = '''def test_memory_plus_server_auto_cloud_credential_is_fail(tmp_path, monkeypatch):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.agent.context_from_memory = True
    monkeypatch.setenv("ANTHROPIC_API_KEY", "canary-provider-secret")

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["memory-context-to-cloud-risk"].status == "fail"
    assert "canary-provider-secret" not in str(report.to_dict(show_paths=True))
    assert report.verdict == "local memory may be sent to cloud inference"
'''
    text = replace_region(
        text,
        "def test_memory_plus_server_auto_cloud_credential_is_fail(",
        "def test_default_nim_endpoint_is_vendor_cloud(",
        second,
        "memory activation composition",
    )

    third = '''def test_explicit_local_deep_research_engine_overrides_server_cloud_capability(
    tmp_path, monkeypatch
):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.deep_research.engine = "ollama"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "canary-provider-secret")
    (tmp_path / "knowledge.db").write_text("", encoding="utf-8")

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert "knowledge-chunks-to-cloud-risk" not in findings
    assert findings["server-cloud-engine-credential-present"].status == "warn"
'''
    text = replace_region(
        text,
        "def test_explicit_local_deep_research_engine_overrides_server_cloud_capability(",
        "def test_knowledge_plus_custom_nim_endpoint_is_warn(",
        third,
        "explicit research engine precedence",
    )

    empty_override = '''def test_empty_nim_host_override_is_not_misclassified_as_vendor_default(
    tmp_path, monkeypatch
):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.engine.default = "nim"
    monkeypatch.setenv("NIM_HOST", "")

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["nim-custom-endpoint-configured"].status == "warn"
    assert "nim-vendor-cloud-default-endpoint" not in findings
'''
    marker = "def test_knowledge_plus_default_nim_is_fail("
    if "def test_empty_nim_host_override_is_not_misclassified_as_vendor_default(" not in text:
        idx = text.find(marker)
        if idx < 0:
            raise RuntimeError("empty NIM override insertion marker not found")
        text = text[:idx] + empty_override.rstrip() + "\n\n\n" + text[idx:]

    compile(text, str(SECURITY_TEST), "exec")
    SECURITY_TEST.write_text(text, encoding="utf-8")


def move_helper_test() -> None:
    CORE_TEST.parent.mkdir(parents=True, exist_ok=True)
    core_test = '''from __future__ import annotations

from openjarvis.core.cloud_activation import (
    SERVER_AUTO_CLOUD_ENGINE_ENV_VARS,
    active_server_cloud_credentials,
)


def test_server_cloud_activation_declaration_is_immutable():
    assert isinstance(SERVER_AUTO_CLOUD_ENGINE_ENV_VARS, frozenset)
    assert "ANTHROPIC_API_KEY" in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS
    assert "GEMINI_API_KEY" in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS


def test_active_server_cloud_credentials_filters_empty_values_and_returns_names_only():
    environ = {
        "ANTHROPIC_API_KEY": "canary-provider-secret",
        "GEMINI_API_KEY": "",
        "UNRELATED": "value",
    }

    active = active_server_cloud_credentials(environ)

    assert active == ("ANTHROPIC_API_KEY",)
    assert "canary-provider-secret" not in str(active)
'''
    compile(core_test, str(CORE_TEST), "exec")
    CORE_TEST.write_text(core_test, encoding="utf-8")
    if OLD_TEST.exists():
        OLD_TEST.unlink()
    if OLD_HELPER.exists():
        OLD_HELPER.unlink()


if __name__ == "__main__":
    patch_scanner()
    patch_cli_test()
    patch_security_test()
    move_helper_test()
