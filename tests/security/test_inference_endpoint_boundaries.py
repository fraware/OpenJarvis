from __future__ import annotations

from openjarvis.core.config import JarvisConfig
from openjarvis.security.data_boundary_audit import build_data_boundary_report


def _config() -> JarvisConfig:
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
    config.learning.spec_search.teacher_model = ""
    config.tools.enabled = ""
    config.tools.mcp.enabled = False
    config.tools.storage.enabled = False
    config.optimize.optimizer_provider = ""
    config.optimize.judge_model = ""
    config.server.host = "127.0.0.1"
    config.server.model = ""
    config.security.profile = "personal"
    config.security.local_engine_bypass = False
    config.intelligence.provider = ""
    config.intelligence.preferred_engine = ""
    config.intelligence.default_model = ""
    config.engine.default = "ollama"
    config.deep_research.engine = ""
    config.deep_research.model = ""
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


def _findings(report):
    return {finding.id: finding for finding in report.findings}


def test_remote_vllm_default_is_external_and_memory_composition_fails(tmp_path) -> None:
    config = _config()
    config.engine.default = "vllm"
    config.engine.vllm.host = "https://cluster.example.test"
    config.agent.context_from_memory = True

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["inference-endpoint-external-engine-default"].status == "warn"
    assert findings["memory-context-to-external-inference-risk"].status == "fail"
    assert "memory-context-to-cloud-risk" not in findings
    assert "cluster.example.test" not in str(report.to_dict(show_paths=True))


def test_loopback_vllm_default_keeps_memory_local(tmp_path) -> None:
    config = _config()
    config.engine.default = "vllm"
    config.engine.vllm.host = "http://127.0.0.1:8000"
    config.agent.context_from_memory = True

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert "inference-endpoint-external-engine-default" not in findings
    assert "memory-context-to-external-inference-risk" not in findings
    assert findings["memory-context-injection-enabled"].status == "info"


def test_nim_default_endpoint_is_vendor_cloud_for_memory(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("NIM_HOST", raising=False)
    config = _config()
    config.engine.default = "nim"
    config.agent.context_from_memory = True

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["cloud-default-engine-configured"].status == "warn"
    assert findings["memory-context-to-cloud-risk"].status == "fail"
    assert "inference-endpoint-external-engine-default" not in findings


def test_nim_loopback_override_keeps_memory_local(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("NIM_HOST", "http://localhost:8000")
    config = _config()
    config.engine.default = "nim"
    config.agent.context_from_memory = True

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert "cloud-default-engine-configured" not in findings
    assert "memory-context-to-cloud-risk" not in findings
    assert "memory-context-to-external-inference-risk" not in findings
    assert findings["memory-context-injection-enabled"].status == "info"


def test_nim_remote_override_is_external_without_emitting_host(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("NIM_HOST", "https://private-nim.example.test")
    config = _config()
    config.engine.default = "nim"
    config.agent.context_from_memory = True

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["inference-endpoint-external-engine-default"].status == "warn"
    assert findings["memory-context-to-external-inference-risk"].status == "fail"
    assert "memory-context-to-cloud-risk" not in findings
    assert "private-nim.example.test" not in str(report.to_dict(show_paths=True))


def test_remote_deep_research_endpoint_fails_knowledge_composition(tmp_path) -> None:
    config = _config()
    config.deep_research.engine = "vllm"
    config.engine.vllm.host = "https://research.example.test"
    config.agent.default_agent = "deep_research"
    (tmp_path / "knowledge.db").write_text("", encoding="utf-8")

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["inference-endpoint-external-deep-research-engine"].status == "warn"
    assert findings["knowledge-chunks-to-external-inference-risk"].status == "fail"
    assert "knowledge-chunks-to-cloud-risk" not in findings
    assert "research.example.test" not in str(report.to_dict(show_paths=True))


def test_unknown_primary_engine_boundary_is_not_assumed_local(tmp_path) -> None:
    config = _config()
    config.engine.default = "future_engine"
    config.agent.context_from_memory = True

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert (
        findings["inference-endpoint-boundary-unknown-engine-default"].status == "warn"
    )
    assert findings["memory-context-to-unknown-inference-boundary"].status == "warn"
    assert "memory-context-injection-enabled" not in findings


def test_external_spec_search_teacher_is_fail(tmp_path) -> None:
    config = _config()
    config.learning.spec_search.enabled = True
    config.learning.spec_search.teacher_engine = "vllm"
    config.learning.spec_search.teacher_model = "teacher"
    config.engine.vllm.host = "https://teacher.example.test"

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["spec-search-external-teacher-enabled"].status == "fail"
    assert "teacher.example.test" not in str(report.to_dict(show_paths=True))


def test_external_optimizer_endpoint_activates_security_surface(tmp_path) -> None:
    config = _config()
    config.optimize.optimizer_provider = "vllm"
    config.engine.vllm.host = "https://optimizer.example.test"
    config.security.local_engine_bypass = True

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert (
        findings["inference-endpoint-external-optimize-optimizer-provider"].status
        == "warn"
    )
    assert findings["security-local-engine-bypass-enabled"].status == "warn"
    assert "optimizer.example.test" not in str(report.to_dict(show_paths=True))
