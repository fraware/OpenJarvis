from __future__ import annotations

from click.testing import CliRunner

from openjarvis.cli.scan_cmd import scan
from openjarvis.core.config import JarvisConfig
from openjarvis.security.data_boundary_audit import SERVER_AUTO_CLOUD_ENGINE_ENV_VARS


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


def test_strict_mode_fails_when_server_cloud_engine_can_auto_activate(
    monkeypatch, tmp_path
):
    for env_name in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS:
        monkeypatch.delenv(env_name, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "canary-openai-secret")

    config = _low_noise_config()
    monkeypatch.setattr(
        "openjarvis.cli.scan_cmd._load_data_boundary_config",
        lambda: (config, tmp_path, True, "", ""),
    )
    monkeypatch.setattr("openjarvis.cli.scan_cmd.get_config_dir", lambda: tmp_path)

    result = CliRunner().invoke(scan, ["--data-boundaries", "--strict"])

    assert result.exit_code == 1
    assert "Cloud inference can be activated automatically" in result.output
    assert "canary-openai-secret" not in result.output
