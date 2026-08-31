from pathlib import Path

scanner = Path("src/openjarvis/security/data_boundary_audit.py")
text = scanner.read_text(encoding="utf-8")

old_import = "from openjarvis.core.credentials import TOOL_CREDENTIALS\n"
new_import = '''from openjarvis.core.credentials import TOOL_CREDENTIALS
from openjarvis.core.inference_boundaries import EndpointBoundary, resolve_engine_boundary
'''
assert old_import in text
text = text.replace(old_import, new_import, 1)

start = text.index("\nLOCAL_ENGINE_KEYS = {")
end = text.index("\nAPI_KEY_ENV_VARS = {", start)
text = text[:start] + "\n" + text[end:]

old_build = '''        _audit_outbound_settings(config, builder)
        _audit_telemetry_settings(config, builder)
'''
new_build = '''        _audit_outbound_settings(config, builder)
        _audit_inference_endpoint_boundaries(config, builder)
        _audit_telemetry_settings(config, builder)
'''
assert old_build in text
text = text.replace(old_build, new_build, 1)


def replace_function(source: str, name: str, next_name: str, replacement: str) -> str:
    begin = source.index(f"def {name}(")
    finish = source.index(f"\ndef {next_name}(", begin)
    return source[:begin] + replacement.rstrip() + "\n\n" + source[finish + 1 :]


outbound = r'''def _audit_inference_endpoint_boundaries(
    config: Any,
    builder: _FindingBuilder,
) -> None:
    """Report explicit inference engines whose endpoint locality needs review."""

    targets: list[tuple[str, Any, Any]] = [
        (
            "intelligence.provider",
            _get(config, "intelligence.provider", ""),
            _get(config, "intelligence.default_model", ""),
        ),
        (
            "intelligence.preferred_engine",
            _get(config, "intelligence.preferred_engine", ""),
            _get(config, "intelligence.default_model", ""),
        ),
        (
            "engine.default",
            _get(config, "engine.default", ""),
            _get(config, "intelligence.default_model", ""),
        ),
        (
            "deep_research.engine",
            _get(config, "deep_research.engine", ""),
            _get(config, "deep_research.model", ""),
        ),
        (
            "optimize.optimizer_provider",
            _get(config, "optimize.optimizer_provider", ""),
            _get(config, "optimize.judge_model", ""),
        ),
    ]
    if bool(_get(config, "learning.spec_search.enabled", False)):
        targets.append(
            (
                "learning.spec_search.teacher_engine",
                _get(config, "learning.spec_search.teacher_engine", ""),
                _get(config, "learning.spec_search.teacher_model", ""),
            )
        )

    for dotted_path, engine, model in targets:
        engine_text = str(engine or "").strip()
        if not engine_text:
            continue
        boundary, source = _target_boundary(config, engine_text, model)
        normalized = dotted_path.replace(".", "-").replace("_", "-")
        if boundary is EndpointBoundary.EXTERNAL_NETWORK:
            builder.add(
                finding_id=f"inference-endpoint-external-{normalized}",
                status="warn",
                title="Inference engine endpoint leaves the local host",
                potential_data_path="inference request context -> external network endpoint",
                evidence=(
                    f"{dotted_path} resolves to {boundary.value} via {source}; "
                    "configured endpoint value was not emitted"
                ),
                recommendation=(
                    "Review the endpoint trust boundary before sending sensitive "
                    "prompt, memory, tool, or research context to this engine."
                ),
            )
        elif boundary is EndpointBoundary.UNKNOWN:
            builder.add(
                finding_id=f"inference-endpoint-boundary-unknown-{normalized}",
                status="warn",
                title="Inference engine endpoint boundary is unknown",
                potential_data_path="inference request context -> unresolved endpoint boundary",
                evidence=f"{dotted_path} boundary is unknown via {source}",
                recommendation=(
                    "Classify the engine endpoint before relying on local-only data "
                    "boundary assumptions."
                ),
            )


def _audit_outbound_settings(config: Any, builder: _FindingBuilder) -> None:
    if bool(_get(config, "analytics.enabled", False)):
        builder.add(
            finding_id="analytics-enabled",
            status="info",
            title="Outbound usage analytics are enabled",
            potential_data_path="runtime usage events -> analytics endpoint",
            evidence="analytics.enabled = true",
            recommendation=(
                "Set analytics.enabled = false for no outbound usage analytics. "
                "This finding does not assert that prompt content is sent."
            ),
        )

    provider = _get(config, "intelligence.provider", "")
    provider_boundary, _ = _target_boundary(config, provider, "")
    if provider_boundary is EndpointBoundary.VENDOR_CLOUD:
        builder.add(
            finding_id="cloud-provider-configured",
            status="warn",
            title="Cloud model provider configured",
            potential_data_path=(
                "prompts, memory context, and tool outputs -> cloud provider"
            ),
            evidence=f"intelligence.provider = {_quote(provider)}",
            recommendation=(
                "Review what context is sent before enabling cloud inference, "
                "or use a local provider for local-only operation."
            ),
        )

    default_model = _get(config, "intelligence.default_model", "")
    effective_engine = _first_nonempty(
        _get(config, "intelligence.preferred_engine", ""),
        _get(config, "engine.default", ""),
        provider,
    )
    default_boundary, _ = _target_boundary(config, effective_engine, default_model)
    if default_model and default_boundary is EndpointBoundary.VENDOR_CLOUD:
        builder.add(
            finding_id="cloud-default-model-configured",
            status="warn",
            title="Cloud default model configured",
            potential_data_path="model requests -> default cloud model",
            evidence=f"intelligence.default_model = {_quote(default_model)}",
            recommendation="Use a local default model for local-only operation.",
        )

    preferred_engine = _get(config, "intelligence.preferred_engine", "")
    preferred_boundary, _ = _target_boundary(config, preferred_engine, "")
    if preferred_boundary is EndpointBoundary.VENDOR_CLOUD:
        builder.add(
            finding_id="cloud-preferred-engine-configured",
            status="warn",
            title="Cloud preferred engine configured",
            potential_data_path="model requests -> preferred cloud engine",
            evidence=f"intelligence.preferred_engine = {_quote(preferred_engine)}",
            recommendation="Use a local preferred engine for local-only operation.",
        )

    default_engine = _get(config, "engine.default", "")
    engine_boundary, _ = _target_boundary(config, default_engine, "")
    if engine_boundary is EndpointBoundary.VENDOR_CLOUD:
        builder.add(
            finding_id="cloud-default-engine-configured",
            status="warn",
            title="Cloud default engine configured",
            potential_data_path="model requests -> default cloud engine",
            evidence=f"engine.default = {_quote(default_engine)}",
            recommendation="Use a local default engine for local-only operation.",
        )

    optimize_provider = _get(config, "optimize.optimizer_provider", "")
    optimize_boundary, _ = _target_boundary(config, optimize_provider, "")
    if optimize_boundary is EndpointBoundary.VENDOR_CLOUD:
        builder.add(
            finding_id="cloud-optimizer-provider-configured",
            status="info",
            title="Cloud optimizer provider is configured",
            potential_data_path="optimization context -> optimizer provider",
            evidence=f"optimize.optimizer_provider = {_quote(optimize_provider)}",
            recommendation=(
                "Before running optimization, review whether examples, traces, "
                "or prompts may be sent to this provider."
            ),
        )

    judge_model = _get(config, "optimize.judge_model", "")
    judge_boundary, _ = _target_boundary(config, optimize_provider, judge_model)
    if judge_model and judge_boundary is EndpointBoundary.VENDOR_CLOUD:
        builder.add(
            finding_id="cloud-judge-model-configured",
            status="info",
            title="Cloud judge model appears configured",
            potential_data_path="optimization examples/results -> judge model",
            evidence=f"optimize.judge_model = {_quote(judge_model)}",
            recommendation="Use a local judge model for local-only optimization.",
        )
'''
text = replace_function(
    text,
    "_audit_outbound_settings",
    "_audit_telemetry_settings",
    outbound,
)


deep_research = r'''def _audit_deep_research_settings(config: Any, builder: _FindingBuilder) -> None:
    engine = _get(config, "deep_research.engine", "")
    model = _get(config, "deep_research.model", "")
    effective_engine, effective_model = _effective_deep_research_target(config)
    boundary, _ = _target_boundary(config, effective_engine, effective_model)
    cloud_engine = bool(engine) and boundary is EndpointBoundary.VENDOR_CLOUD
    cloud_model = bool(model) and boundary is EndpointBoundary.VENDOR_CLOUD
    if not cloud_engine and not cloud_model:
        return
    evidence_parts = []
    if cloud_engine:
        evidence_parts.append(f"deep_research.engine = {_quote(engine)}")
    if cloud_model:
        evidence_parts.append(f"deep_research.model = {_quote(model)}")
    builder.add(
        finding_id="deep-research-cloud-configured",
        status="warn",
        title="Cloud deep-research engine or model configured",
        potential_data_path="research planner context -> cloud engine/model",
        evidence="; ".join(evidence_parts),
        recommendation=(
            "Use local deep-research engine and model settings for local-only "
            "operation."
        ),
    )
'''
text = replace_function(
    text,
    "_audit_deep_research_settings",
    "_effective_deep_research_target",
    deep_research,
)


knowledge = r'''def _audit_knowledge_cloud_composition(
    config: Any,
    root: Path,
    builder: _FindingBuilder,
) -> None:
    """Flag local knowledge chunks routed toward outbound Deep Research inference."""
    tools = _configured_tools(config)
    scan_active = _scan_chunks_surface_active(config, tools)
    knowledge_exists = _knowledge_store_exists(root)
    engine, model = _effective_deep_research_target(config)
    boundary, source = _target_boundary(config, engine, model)
    outbound = boundary.leaves_local_host is True

    if knowledge_exists and outbound:
        evidence_parts = [
            "knowledge.db exists",
            (
                "effective deep_research engine = "
                f"{_quote(engine) if engine else '<empty>'}"
            ),
            (
                "effective deep_research model = "
                f"{_quote(model) if model else '<empty>'}"
            ),
            f"endpoint boundary = {boundary.value} via {source}",
            "configured endpoint value was not emitted",
        ]
        if tools & KNOWLEDGE_ENGINE_TOOLS:
            evidence_parts.append(
                f"configured tool(s) = {_format_tools(tools & KNOWLEDGE_ENGINE_TOOLS)}"
            )
        else:
            evidence_parts.append(
                "deep research auto-installs scan_chunks when knowledge.db exists"
            )
        is_vendor = boundary is EndpointBoundary.VENDOR_CLOUD
        builder.add(
            finding_id=(
                "knowledge-chunks-to-cloud-risk"
                if is_vendor
                else "knowledge-chunks-to-external-inference-risk"
            ),
            status="fail",
            title=(
                "Local knowledge chunks may be sent to cloud inference"
                if is_vendor
                else "Local knowledge chunks may leave the local host for inference"
            ),
            potential_data_path=(
                "local knowledge.db chunks -> scan_chunks / Deep Research -> "
                + ("cloud inference" if is_vendor else "external inference endpoint")
            ),
            evidence="; ".join(evidence_parts),
            recommendation=(
                "Use a local-host Deep Research engine/model when knowledge.db "
                "contains sensitive documents, or review the outbound endpoint "
                "before scanning chunks."
            ),
        )
    elif scan_active:
        if tools & KNOWLEDGE_ENGINE_TOOLS:
            evidence = (
                f"configured tool(s) = {_format_tools(tools & KNOWLEDGE_ENGINE_TOOLS)}"
            )
        else:
            agent_name = _get(config, "agent.default_agent", "")
            evidence = f"agent.default_agent = {_quote(agent_name)}"
        evidence += f"; endpoint boundary = {boundary.value} via {source}"
        status: Status = "info" if boundary.leaves_local_host is False else "warn"
        builder.add(
            finding_id="knowledge-engine-tool-configured",
            status=status,
            title="Knowledge chunk scanning routes local chunks to an inference engine",
            potential_data_path=(
                "local knowledge-store chunks -> configured inference engine"
            ),
            evidence=evidence,
            recommendation=(
                "Review knowledge.db contents and the effective Deep Research "
                "engine/model before scanning sensitive documents."
            ),
        )
'''
text = replace_function(
    text,
    "_audit_knowledge_cloud_composition",
    "_audit_security_settings",
    knowledge,
)


memory = r'''def _audit_memory_cloud_composition(
    config: Any,
    builder: _FindingBuilder,
) -> None:
    context_from_memory = bool(_get(config, "agent.context_from_memory", False))
    active = _primary_inference_signals(config)
    outbound = [(label, boundary) for label, boundary in active if boundary.leaves_local_host]
    unknown = [label for label, boundary in active if boundary is EndpointBoundary.UNKNOWN]

    if context_from_memory and outbound:
        has_vendor = any(
            boundary is EndpointBoundary.VENDOR_CLOUD for _, boundary in outbound
        )
        labels = [f"{label} ({boundary.value})" for label, boundary in outbound]
        builder.add(
            finding_id=(
                "memory-context-to-cloud-risk"
                if has_vendor
                else "memory-context-to-external-inference-risk"
            ),
            status="fail",
            title=(
                "Local memory may be injected into cloud-bound prompts"
                if has_vendor
                else "Local memory may leave the local host in inference prompts"
            ),
            potential_data_path=(
                "indexed local memory -> prompt context -> "
                + ("cloud inference provider" if has_vendor else "external inference endpoint")
            ),
            evidence=(
                "agent.context_from_memory = true; outbound inference setting(s) = "
                + ", ".join(labels)
            ),
            recommendation=(
                "Disable agent.context_from_memory before outbound inference, "
                "or use local-host engines when indexed memory contains sensitive data."
            ),
        )
    elif context_from_memory and unknown:
        builder.add(
            finding_id="memory-context-to-unknown-inference-boundary",
            status="warn",
            title="Memory context injection has an unresolved inference boundary",
            potential_data_path="indexed local memory -> prompt context -> unknown endpoint",
            evidence=(
                "agent.context_from_memory = true; unresolved setting(s) = "
                + ", ".join(unknown)
            ),
            recommendation=(
                "Classify the inference endpoint before injecting sensitive indexed memory."
            ),
        )
    elif context_from_memory:
        builder.add(
            finding_id="memory-context-injection-enabled",
            status="info",
            title="Memory context injection is enabled",
            potential_data_path="indexed local memory -> future prompt context",
            evidence="agent.context_from_memory = true",
            recommendation=(
                "Keep indexed memory scoped to data that may safely appear in future "
                "prompts, especially if outbound engines are enabled later."
            ),
        )
'''
text = replace_function(
    text,
    "_audit_memory_cloud_composition",
    "_audit_trace_and_learning_settings",
    memory,
)

old_spec = '''    spec_search_enabled = bool(_get(config, "learning.spec_search.enabled", False))
    teacher_engine = _get(config, "learning.spec_search.teacher_engine", "")
    teacher_model = _get(config, "learning.spec_search.teacher_model", "")
    if spec_search_enabled and _is_cloud_value(teacher_engine):
        builder.add(
            finding_id="spec-search-cloud-teacher-enabled",
            status="fail",
            title="LLM-guided spec search uses a cloud teacher engine",
            potential_data_path=(
                "diagnostics/spec-search context -> cloud teacher model"
            ),
            evidence=(
                "learning.spec_search.enabled = true; "
                f"teacher_engine = {_quote(teacher_engine)}; "
                f"teacher_model = {_quote(teacher_model)}"
            ),
            recommendation=(
                "Use a local teacher engine/model or keep spec search disabled for "
                "local-only operation."
            ),
        )
'''
new_spec = '''    spec_search_enabled = bool(_get(config, "learning.spec_search.enabled", False))
    teacher_engine = _get(config, "learning.spec_search.teacher_engine", "")
    teacher_model = _get(config, "learning.spec_search.teacher_model", "")
    teacher_boundary, teacher_source = _target_boundary(
        config, teacher_engine, teacher_model
    )
    if spec_search_enabled and teacher_boundary.leaves_local_host:
        is_vendor = teacher_boundary is EndpointBoundary.VENDOR_CLOUD
        builder.add(
            finding_id=(
                "spec-search-cloud-teacher-enabled"
                if is_vendor
                else "spec-search-external-teacher-enabled"
            ),
            status="fail",
            title=(
                "LLM-guided spec search uses a cloud teacher engine"
                if is_vendor
                else "LLM-guided spec search uses an external teacher endpoint"
            ),
            potential_data_path=(
                "diagnostics/spec-search context -> "
                + ("cloud teacher model" if is_vendor else "external teacher endpoint")
            ),
            evidence=(
                "learning.spec_search.enabled = true; "
                f"teacher_engine = {_quote(teacher_engine)}; "
                f"teacher_model = {_quote(teacher_model)}; "
                f"endpoint boundary = {teacher_boundary.value} via {teacher_source}; "
                "configured endpoint value was not emitted"
            ),
            recommendation=(
                "Use a local-host teacher engine/model or keep spec search disabled "
                "for local-only operation."
            ),
        )
'''
assert old_spec in text
text = text.replace(old_spec, new_spec, 1)

cloud_surface = r'''def _has_cloud_api_surface(config: Any | None, active_tools: set[str]) -> bool:
    """True when vendor-cloud inference/API-key surfaces are configured."""
    if any(os.environ.get(name) for name in API_KEY_ENV_VARS):
        return True
    if active_tools & CLOUD_API_SURFACES:
        return True
    if config is None:
        return False
    if any(
        boundary is EndpointBoundary.VENDOR_CLOUD
        for _, boundary in _primary_inference_signals(config)
    ):
        return True
    deep_engine, deep_model = _effective_deep_research_target(config)
    if _target_is_cloud(config, deep_engine, deep_model):
        return True
    optimizer_provider = _get(config, "optimize.optimizer_provider", "")
    if _target_is_cloud(
        config,
        optimizer_provider,
        _get(config, "optimize.judge_model", ""),
    ):
        return True
    if str(_get(config, "speech.backend", "") or "").lower() in {
        "openai",
        "deepgram",
    }:
        return True
    if (
        bool(_get(config, "digest.enabled", False))
        and str(_get(config, "digest.tts_backend", "") or "").lower()
        in CLOUD_TTS_BACKENDS
    ):
        return True
    if bool(_get(config, "learning.spec_search.enabled", False)):
        return _target_is_cloud(
            config,
            _get(config, "learning.spec_search.teacher_engine", ""),
            _get(config, "learning.spec_search.teacher_model", ""),
        )
    return False


def _has_external_surface(config: Any | None, active_tools: set[str]) -> bool:
    """True when external egress or vendor-cloud/API surfaces are present."""
    if active_tools & EXTERNAL_TOOL_SURFACES:
        return True
    if (
        _scan_chunks_surface_active(config, active_tools)
        if config is not None
        else False
    ):
        return True
    if config is not None:
        if any(
            boundary.leaves_local_host is True
            for boundary in _configured_inference_boundaries(config)
        ):
            return True
    return _has_cloud_api_surface(config, active_tools)
'''
text = replace_function(
    text,
    "_has_cloud_api_surface",
    "_has_cloud_or_api_surface",
    cloud_surface,
)

verdict = r'''def _derive_verdict(findings: Iterable[DataBoundaryFinding]) -> str:
    finding_ids = {finding.id for finding in findings}
    statuses = {finding.status for finding in findings}

    if "memory-context-to-cloud-risk" in finding_ids:
        return "local memory may be sent to cloud inference"
    if "memory-context-to-external-inference-risk" in finding_ids:
        return "local memory may be sent to an external inference endpoint"
    if "knowledge-chunks-to-cloud-risk" in finding_ids:
        return "local knowledge may be sent to cloud inference"
    if "knowledge-chunks-to-external-inference-risk" in finding_ids:
        return "local knowledge may be sent to an external inference endpoint"
    if "config-root-error" in finding_ids:
        return "OpenJarvis home must be fixed before full data-boundary review"
    if "config-load-error" in finding_ids:
        return "configuration must be fixed before full data-boundary review"
    if "fail" in statuses:
        return "attention required for application data boundaries"
    if any(fid.startswith("inference-endpoint-external-") for fid in finding_ids):
        return "external inference endpoint data boundaries configured"
    if any(
        fid.startswith("inference-endpoint-boundary-unknown-") for fid in finding_ids
    ):
        return "inference endpoint boundary requires review"
    if any(
        fid in finding_ids
        for fid in {
            "cloud-provider-configured",
            "cloud-preferred-engine-configured",
            "cloud-default-engine-configured",
            "cloud-default-model-configured",
            "cloud-speech-backend-configured",
            "cloud-tts-backend-configured",
            "deep-research-cloud-configured",
        }
    ):
        return "cloud-capable data boundaries configured"
    if "warn" in statuses:
        return "local sensitive stores or optional data flows detected"
    return "no fail or warn findings detected"
'''
text = replace_function(text, "_derive_verdict", "_configured_tools", verdict)

helper_start = text.index("def _is_cloud_value(")
helper_end = text.index("\ndef _looks_like_cloud_model(", helper_start)
helpers = r'''def _is_cloud_value(value: Any) -> bool:
    """Fallback classification for provider aliases without engine metadata."""
    if value is None:
        return False
    text = str(value).strip().lower()
    if not text:
        return False
    return any(key in text for key in CLOUD_PROVIDER_KEYS)


def _target_boundary(
    config: Any,
    engine: Any,
    model: Any,
) -> tuple[EndpointBoundary, str]:
    """Resolve an inference target without emitting configured endpoint values."""
    engine_text = str(engine or "").strip().lower().replace("-", "_")
    if engine_text:
        resolution = resolve_engine_boundary(engine_text, config)
        if resolution.boundary is not EndpointBoundary.UNKNOWN:
            return resolution.boundary, resolution.source
        if _is_cloud_value(engine_text):
            return EndpointBoundary.VENDOR_CLOUD, "provider-alias"
        if resolution.source == "runtime":
            return EndpointBoundary.UNKNOWN, "runtime"
    if _looks_like_cloud_model(model):
        return EndpointBoundary.VENDOR_CLOUD, "model"
    return EndpointBoundary.UNKNOWN, "unclassified"


def _target_is_cloud(config: Any, engine: Any, model: Any) -> bool:
    boundary, _ = _target_boundary(config, engine, model)
    return boundary is EndpointBoundary.VENDOR_CLOUD


def _primary_inference_signals(
    config: Any,
) -> list[tuple[str, EndpointBoundary]]:
    """Return redaction-safe boundary signals for primary inference settings."""
    provider = _get(config, "intelligence.provider", "")
    preferred_engine = _get(config, "intelligence.preferred_engine", "")
    default_engine = _get(config, "engine.default", "")
    default_model = _get(config, "intelligence.default_model", "")
    signals: list[tuple[str, EndpointBoundary]] = []
    for dotted_path, engine in (
        ("intelligence.provider", provider),
        ("intelligence.preferred_engine", preferred_engine),
        ("engine.default", default_engine),
    ):
        if not str(engine or "").strip():
            continue
        boundary, _ = _target_boundary(config, engine, "")
        signals.append((dotted_path, boundary))

    effective_engine = _first_nonempty(preferred_engine, default_engine, provider)
    if default_model:
        boundary, _ = _target_boundary(config, effective_engine, default_model)
        if boundary is not EndpointBoundary.UNKNOWN:
            signals.append(("intelligence.default_model", boundary))
    return signals


def _configured_inference_boundaries(config: Any) -> list[EndpointBoundary]:
    boundaries = [boundary for _, boundary in _primary_inference_signals(config)]
    deep_engine, deep_model = _effective_deep_research_target(config)
    deep_boundary, _ = _target_boundary(config, deep_engine, deep_model)
    boundaries.append(deep_boundary)

    optimizer_provider = _get(config, "optimize.optimizer_provider", "")
    optimizer_model = _get(config, "optimize.judge_model", "")
    if optimizer_provider or optimizer_model:
        optimizer_boundary, _ = _target_boundary(
            config, optimizer_provider, optimizer_model
        )
        boundaries.append(optimizer_boundary)

    if bool(_get(config, "learning.spec_search.enabled", False)):
        teacher_boundary, _ = _target_boundary(
            config,
            _get(config, "learning.spec_search.teacher_engine", ""),
            _get(config, "learning.spec_search.teacher_model", ""),
        )
        boundaries.append(teacher_boundary)
    return boundaries
'''
text = text[:helper_start] + helpers.rstrip() + "\n\n" + text[helper_end + 1 :]

assert "LOCAL_ENGINE_KEYS" not in text
assert "_is_local_engine_value" not in text
assert "_primary_cloud_signals" not in text
scanner.write_text(text, encoding="utf-8")


test_path = Path("tests/security/test_inference_endpoint_boundaries.py")
test_path.write_text(
    r'''from __future__ import annotations

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

    assert (
        findings["inference-endpoint-external-deep-research-engine"].status == "warn"
    )
    assert findings["knowledge-chunks-to-external-inference-risk"].status == "fail"
    assert "knowledge-chunks-to-cloud-risk" not in findings
    assert "research.example.test" not in str(report.to_dict(show_paths=True))


def test_unknown_primary_engine_boundary_is_not_assumed_local(tmp_path) -> None:
    config = _config()
    config.engine.default = "future_engine"
    config.agent.context_from_memory = True

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["inference-endpoint-boundary-unknown-engine-default"].status == "warn"
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
''',
    encoding="utf-8",
)
