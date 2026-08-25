from __future__ import annotations

import subprocess
import sys

from openjarvis.core.cloud_activation import SERVER_AUTO_CLOUD_ENGINE_ENV_VARS
from openjarvis.core.config import JarvisConfig
from openjarvis.security.data_boundary_audit import (
    _CONFIG_STORE_PATHS,
    API_KEY_ENV_VARS,
    build_data_boundary_report,
)


def _ids(report):
    return {finding.id for finding in report.findings}


def _findings(report):
    return {finding.id: finding for finding in report.findings}


def _low_noise_config() -> JarvisConfig:
    config = JarvisConfig()
    config.analytics.enabled = False
    config.traces.enabled = False
    config.telemetry.enabled = False
    config.agent.context_from_memory = False
    config.agent.tools = ""
    config.agent.default_agent = "simple"
    config.skills.enabled = False
    config.digest.enabled = False
    config.channel.enabled = False
    config.learning.enabled = False
    config.learning.training_enabled = False
    config.learning.auto_update = False
    config.learning.spec_search.enabled = False
    config.learning.spec_search.teacher_engine = ""
    config.tools.enabled = ""
    config.tools.mcp.enabled = False
    config.tools.storage.enabled = False
    config.optimize.optimizer_provider = ""
    config.optimize.judge_model = ""
    config.server.host = "127.0.0.1"
    config.server.model = ""
    config.security.profile = "personal"
    config.intelligence.provider = ""
    config.intelligence.preferred_engine = ""
    config.intelligence.default_model = ""
    config.engine.default = "ollama"
    config.deep_research.engine = ""
    config.deep_research.model = ""
    config.speech.backend = ""

    # Keep the scan rooted entirely in tmp_path during tests.
    config.traces.db_path = ""
    config.telemetry.db_path = ""
    config.security.audit_log_path = ""
    config.security.vault_key_path = ""
    config.tools.storage.db_path = ""
    config.tools.storage.facts_path = ""
    config.sessions.db_path = ""
    config.agent_manager.db_path = ""
    config.optimize.db_path = ""
    config.scheduler.db_path = ""
    config.skills.index_dir = ""
    config.memory_files.soul_path = ""
    config.memory_files.memory_path = ""
    config.memory_files.user_path = ""
    return config


def _clear_boundary_env(monkeypatch) -> None:
    names = set(API_KEY_ENV_VARS) | set(SERVER_AUTO_CLOUD_ENGINE_ENV_VARS)
    names.update({"NIM_HOST", "NIM_API_KEY", "DEEPGRAM_API_KEY"})
    for name in names:
        monkeypatch.delenv(name, raising=False)


def test_server_auto_cloud_credential_is_warn_without_cloud_config(
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


def test_memory_plus_server_auto_cloud_credential_is_fail(tmp_path, monkeypatch):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.agent.context_from_memory = True
    monkeypatch.setenv("ANTHROPIC_API_KEY", "canary-provider-secret")

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["memory-context-to-cloud-risk"].status == "fail"
    assert "canary-provider-secret" not in str(report.to_dict(show_paths=True))
    assert report.verdict == "local memory may be sent to cloud inference"


def test_default_nim_endpoint_is_vendor_cloud(tmp_path, monkeypatch):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.engine.default = "nim"

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["nim-vendor-cloud-default-endpoint"].status == "warn"
    assert "nim-custom-endpoint-configured" not in findings
    assert report.verdict == "cloud-capable data boundaries configured"


def test_memory_plus_default_nim_is_fail(tmp_path, monkeypatch):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.engine.default = "nim"
    config.agent.context_from_memory = True

    report = build_data_boundary_report(config, tmp_path)

    assert _findings(report)["memory-context-to-cloud-risk"].status == "fail"
    assert report.verdict == "local memory may be sent to cloud inference"


def test_custom_nim_endpoint_is_unknown_and_redacted(tmp_path, monkeypatch):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.engine.default = "nim"
    config.agent.context_from_memory = True
    custom_host = "https://nim-private.example.internal:8443"
    monkeypatch.setenv("NIM_HOST", custom_host)

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["nim-custom-endpoint-configured"].status == "warn"
    assert findings["memory-context-to-custom-nim-endpoint-risk"].status == "warn"
    assert "nim-vendor-cloud-default-endpoint" not in findings
    assert "memory-context-to-cloud-risk" not in findings
    assert custom_host not in str(report.to_dict(show_paths=True))
    assert report.verdict == "custom NIM endpoint requires data-boundary review"


def test_empty_nim_host_uses_vendor_default(tmp_path, monkeypatch):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.engine.default = "nim"
    monkeypatch.setenv("NIM_HOST", "")

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["nim-vendor-cloud-default-endpoint"].status == "warn"
    assert "nim-custom-endpoint-configured" not in findings


def test_knowledge_plus_default_nim_is_fail(tmp_path, monkeypatch):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.engine.default = "nim"
    (tmp_path / "knowledge.db").write_text("", encoding="utf-8")

    report = build_data_boundary_report(config, tmp_path)

    assert _findings(report)["knowledge-chunks-to-cloud-risk"].status == "fail"
    assert report.verdict == "local knowledge may be sent to cloud inference"


def test_explicit_local_deep_research_engine_overrides_server_cloud_capability(
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


def test_knowledge_plus_custom_nim_endpoint_is_warn(tmp_path, monkeypatch):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.engine.default = "nim"
    monkeypatch.setenv("NIM_HOST", "https://nim-private.example.internal:8443")
    (tmp_path / "knowledge.db").write_text("", encoding="utf-8")

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["knowledge-chunks-to-custom-nim-endpoint-risk"].status == "warn"
    assert "knowledge-chunks-to-cloud-risk" not in findings


def test_nim_api_key_is_specialized_and_redacted_when_nim_active(tmp_path, monkeypatch):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.engine.default = "nim"
    monkeypatch.setenv("NIM_API_KEY", "canary-nim-secret")

    report = build_data_boundary_report(config, tmp_path)
    finding = _findings(report)["env-credential-nim_api_key"]

    assert finding.status == "warn"
    assert "canary-nim-secret" not in str(report.to_dict(show_paths=True))


def test_deepgram_api_key_is_specialized_and_redacted_when_active(
    tmp_path, monkeypatch
):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.speech.backend = "deepgram"
    monkeypatch.setenv("DEEPGRAM_API_KEY", "canary-deepgram-secret")

    report = build_data_boundary_report(config, tmp_path)
    finding = _findings(report)["env-credential-deepgram_api_key"]

    assert finding.status == "warn"
    assert "canary-deepgram-secret" not in str(report.to_dict(show_paths=True))


def test_custom_agent_manager_db_path_is_audited(tmp_path, monkeypatch):
    _clear_boundary_env(monkeypatch)
    root = tmp_path / "home"
    root.mkdir()
    custom_db = tmp_path / "state" / "managed-agents.sqlite"
    custom_db.parent.mkdir()
    custom_db.write_text("", encoding="utf-8")

    config = _low_noise_config()
    config.agent_manager.db_path = str(custom_db)

    report = build_data_boundary_report(config, root)
    finding = _findings(report)["local-store-agents-db"]

    assert finding.absolute_location == str(custom_db)
    assert finding.location == "<redacted>"


def test_data_boundary_import_does_not_load_engine_package():
    code = (
        "import sys; "
        "import openjarvis.security.data_boundary_audit; "
        "assert 'openjarvis.engine' not in sys.modules, "
        "'data-boundary diagnostics must stay independent of engine imports'"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_config_store_paths_resolve_against_jarvis_config_schema():
    config = JarvisConfig()

    for finding_id, _title, dotted_path, _status in _CONFIG_STORE_PATHS:
        current = config
        for part in dotted_path.split("."):
            assert hasattr(current, part), (
                f"{finding_id}: config path {dotted_path!r} does not resolve; "
                f"missing component {part!r}"
            )
            current = getattr(current, part)
