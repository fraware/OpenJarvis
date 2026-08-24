"""Apply the data-boundary runtime-parity patch on the feature branch.

Temporary branch-local helper used to make exact, assertion-guarded edits to the
large audit module. The helper is removed before the pull request is opened.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "src/openjarvis/security/data_boundary_audit.py"
DOC = ROOT / "docs/user-guide/data-boundary-scan.md"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def patch_audit() -> None:
    text = AUDIT.read_text(encoding="utf-8")

    text = replace_once(
        text,
        '    "DEEPSEEK_API_KEY": ("DeepSeek cloud inference", {"deepseek"}),\n',
        '    "DEEPGRAM_API_KEY": ("Deepgram cloud speech-to-text", {"deepgram"}),\n'
        '    "DEEPSEEK_API_KEY": ("DeepSeek cloud inference", {"deepseek"}),\n',
        "Deepgram credential",
    )
    text = replace_once(
        text,
        '    "OPENAI_API_KEY": ("OpenAI cloud inference", {"openai", "gpt"}),\n',
        '    "NIM_API_KEY": ("NVIDIA NIM API authentication", {"nim"}),\n'
        '    "OPENAI_API_KEY": ("OpenAI cloud inference", {"openai", "gpt"}),\n',
        "NIM credential",
    )
    text = replace_once(
        text,
        '    "TAVILY_API_KEY": ("Tavily web search", {"tavily", "web_search"}),\n'
        '}\n\n'
        'CHANNEL_SECRET_FIELDS:',
        '    "TAVILY_API_KEY": ("Tavily web search", {"tavily", "web_search"}),\n'
        '}\n\n'
        '# `jarvis serve` automatically constructs a cloud engine when any of\n'
        '# these credentials are present. Keep this explicit until runtime and\n'
        '# diagnostics share one capability descriptor (follow-up architecture).\n'
        'SERVER_AUTO_CLOUD_ENGINE_ENV_VARS = frozenset(\n'
        '    {\n'
        '        "ANTHROPIC_API_KEY",\n'
        '        "GEMINI_API_KEY",\n'
        '        "GOOGLE_API_KEY",\n'
        '        "OPENAI_API_KEY",\n'
        '        "OPENROUTER_API_KEY",\n'
        '    }\n'
        ')\n\n'
        'CHANNEL_SECRET_FIELDS:',
        "server cloud activation constants",
    )

    text = replace_once(
        text,
        '("agents-db", "Agent manager database", "agents.db_path", "warn"),',
        '("agents-db", "Agent manager database", "agent_manager.db_path", "warn"),',
        "agent manager config path",
    )

    text = replace_once(
        text,
        '        _audit_outbound_settings(config, builder)\n'
        '        _audit_telemetry_settings(config, builder)\n',
        '        _audit_outbound_settings(config, builder)\n'
        '        _audit_nim_settings(config, builder)\n'
        '        _audit_telemetry_settings(config, builder)\n',
        "NIM audit call",
    )
    text = replace_once(
        text,
        '    _audit_channel_environment_credentials(active_config, builder)\n'
        '    _audit_generic_runtime_credentials(builder)\n'
        '    if _has_cloud_api_surface(active_config, active_tools):\n',
        '    _audit_channel_environment_credentials(active_config, builder)\n'
        '    _audit_generic_runtime_credentials(builder)\n'
        '    _audit_server_cloud_engine_activation(builder)\n'
        '    if _has_cloud_api_surface(active_config, active_tools):\n',
        "server cloud activation audit call",
    )

    helper_block = '''\n\ndef _server_auto_cloud_envs() -> list[str]:
    """Return server cloud-engine activation keys that are present.

    Presence is sufficient because ``jarvis serve`` uses the same condition to
    construct a cloud engine. Values are never read or printed.
    """
    return sorted(
        name for name in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS if os.environ.get(name)
    )


def _audit_server_cloud_engine_activation(builder: _FindingBuilder) -> None:
    active = _server_auto_cloud_envs()
    if not active:
        return
    builder.add(
        finding_id="server-cloud-engine-credential-present",
        status="warn",
        title="Cloud inference can be activated automatically by server credentials",
        potential_data_path="process cloud credentials -> jarvis serve -> cloud engine",
        evidence=(
            "credential variable(s) set: "
            + ", ".join(active)
            + "; values were not read or printed"
        ),
        recommendation=(
            "Unset these variables for strict local-only server operation, or review "
            "the cloud engine/model routes that may become available."
        ),
    )


def _is_nim_engine_value(value: Any) -> bool:
    text = str(value or "").strip().lower().replace("-", "_")
    return text == "nim"


def _primary_effective_engine(config: Any) -> str:
    return _first_nonempty(
        _get(config, "intelligence.preferred_engine", ""),
        _get(config, "engine.default", ""),
        _get(config, "intelligence.provider", ""),
    )


def _nim_uses_default_vendor_host(engine: Any) -> bool:
    return _is_nim_engine_value(engine) and not bool(os.environ.get("NIM_HOST"))


def _nim_uses_custom_host(engine: Any) -> bool:
    return _is_nim_engine_value(engine) and bool(os.environ.get("NIM_HOST"))


def _configured_nim_paths(config: Any) -> list[str]:
    paths = (
        "intelligence.provider",
        "intelligence.preferred_engine",
        "engine.default",
        "deep_research.engine",
    )
    return [path for path in paths if _is_nim_engine_value(_get(config, path, ""))]


def _audit_nim_settings(config: Any, builder: _FindingBuilder) -> None:
    paths = _configured_nim_paths(config)
    if not paths:
        return
    selected = ", ".join(f"{path} = 'nim'" for path in paths)
    if os.environ.get("NIM_HOST"):
        builder.add(
            finding_id="nim-custom-endpoint-configured",
            status="warn",
            title="NVIDIA NIM uses a custom endpoint with unknown locality",
            potential_data_path="model requests -> custom NIM endpoint",
            evidence=f"{selected}; NIM_HOST is set; value was not read or printed",
            recommendation=(
                "Verify that the custom NIM endpoint is within the intended trust "
                "boundary before sending sensitive prompts or local context."
            ),
        )
        return
    builder.add(
        finding_id="nim-vendor-cloud-default-endpoint",
        status="warn",
        title="NVIDIA NIM uses the NVIDIA-hosted endpoint by default",
        potential_data_path="model requests -> NVIDIA-hosted NIM API",
        evidence=f"{selected}; NIM_HOST is not set",
        recommendation=(
            "Set NIM_HOST to an explicitly reviewed self-hosted endpoint, or choose "
            "a local engine for strict local-only operation."
        ),
    )
'''
    text = replace_once(
        text,
        "\n\ndef _audit_environment_credentials(\n",
        helper_block + "\n\ndef _audit_environment_credentials(\n",
        "runtime parity helper block",
    )

    text = replace_once(
        text,
        '        active = any(alias in value for alias in aliases for value in active_values)\n'
        '        status: Status = "warn" if active else "info"\n',
        '        active = env_name in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS or any(\n'
        '            alias in value for alias in aliases for value in active_values\n'
        '        )\n'
        '        status: Status = "warn" if active else "info"\n',
        "credential activation parity",
    )

    text = replace_once(
        text,
        '    engine, model = _effective_deep_research_target(config)\n'
        '    cloud_target = _target_is_cloud(engine, model)\n\n'
        '    if knowledge_exists and cloud_target:\n',
        '    engine, model = _effective_deep_research_target(config)\n'
        '    server_cloud_envs = _server_auto_cloud_envs()\n'
        '    nim_vendor_cloud = _nim_uses_default_vendor_host(engine)\n'
        '    nim_custom_host = _nim_uses_custom_host(engine)\n'
        '    cloud_target = (\n'
        '        _target_is_cloud(engine, model)\n'
        '        or nim_vendor_cloud\n'
        '        or bool(server_cloud_envs)\n'
        '    )\n\n'
        '    if knowledge_exists and cloud_target:\n',
        "knowledge cloud target parity",
    )
    text = replace_once(
        text,
        '        if tools & KNOWLEDGE_ENGINE_TOOLS:\n'
        '            evidence_parts.append(\n',
        '        if server_cloud_envs:\n'
        '            evidence_parts.append(\n'
        '                "server cloud-engine credential(s) present: "\n'
        '                + ", ".join(server_cloud_envs)\n'
        '            )\n'
        '        if nim_vendor_cloud:\n'
        '            evidence_parts.append(\n'
        '                "NIM_HOST is not set; NIM uses the NVIDIA-hosted default"\n'
        '            )\n'
        '        if tools & KNOWLEDGE_ENGINE_TOOLS:\n'
        '            evidence_parts.append(\n',
        "knowledge cloud evidence",
    )
    text = replace_once(
        text,
        '    elif scan_active:\n'
        '        if tools & KNOWLEDGE_ENGINE_TOOLS:\n',
        '    elif knowledge_exists and nim_custom_host:\n'
        '        builder.add(\n'
        '            finding_id="knowledge-chunks-to-custom-nim-endpoint-risk",\n'
        '            status="warn",\n'
        '            title="Local knowledge chunks may reach a custom NIM endpoint",\n'
        '            potential_data_path=(\n'
        '                "local knowledge.db chunks -> Deep Research -> custom NIM endpoint"\n'
        '            ),\n'
        '            evidence=(\n'
        '                "knowledge.db exists; NIM_HOST is set; value was not read "\n'
        '                "or printed"\n'
        '            ),\n'
        '            recommendation=(\n'
        '                "Verify the NIM endpoint trust boundary before scanning "\n'
        '                "sensitive local knowledge."\n'
        '            ),\n'
        '        )\n'
        '    elif scan_active:\n'
        '        if tools & KNOWLEDGE_ENGINE_TOOLS:\n',
        "custom NIM knowledge composition",
    )

    text = replace_once(
        text,
        '    context_from_memory = bool(_get(config, "agent.context_from_memory", False))\n'
        '    active_cloud = _primary_cloud_signals(config)\n\n'
        '    if context_from_memory and active_cloud:\n',
        '    context_from_memory = bool(_get(config, "agent.context_from_memory", False))\n'
        '    active_cloud = _primary_cloud_signals(config)\n'
        '    custom_nim = _nim_uses_custom_host(_primary_effective_engine(config))\n\n'
        '    if context_from_memory and active_cloud:\n',
        "memory custom NIM detection",
    )
    text = replace_once(
        text,
        '    elif context_from_memory:\n'
        '        builder.add(\n'
        '            finding_id="memory-context-injection-enabled",\n',
        '    elif context_from_memory and custom_nim:\n'
        '        builder.add(\n'
        '            finding_id="memory-context-to-custom-nim-endpoint-risk",\n'
        '            status="warn",\n'
        '            title="Local memory may be injected into a custom NIM endpoint",\n'
        '            potential_data_path=(\n'
        '                "indexed local memory -> prompt context -> custom NIM endpoint"\n'
        '            ),\n'
        '            evidence=(\n'
        '                "agent.context_from_memory = true; NIM_HOST is set; "\n'
        '                "value was not read or printed"\n'
        '            ),\n'
        '            recommendation=(\n'
        '                "Verify the custom NIM endpoint trust boundary, or disable "\n'
        '                "memory context injection for sensitive local memory."\n'
        '            ),\n'
        '        )\n'
        '    elif context_from_memory:\n'
        '        builder.add(\n'
        '            finding_id="memory-context-injection-enabled",\n',
        "custom NIM memory composition",
    )

    text = replace_once(
        text,
        '    effective_engine = _first_nonempty(preferred_engine, default_engine, provider)\n'
        '    if not signals and _target_is_cloud(effective_engine, default_model):\n',
        '    signals.extend(\n'
        '        f"{name} activates the server cloud engine"\n'
        '        for name in _server_auto_cloud_envs()\n'
        '    )\n'
        '    effective_engine = _first_nonempty(preferred_engine, default_engine, provider)\n'
        '    if _nim_uses_default_vendor_host(effective_engine):\n'
        '        signals.append("NIM uses the NVIDIA-hosted default endpoint")\n'
        '    if not signals and _target_is_cloud(effective_engine, default_model):\n',
        "primary cloud signals parity",
    )

    text = replace_once(
        text,
        '            "deep-research-cloud-configured",\n'
        '        }\n'
        '    ):\n'
        '        return "cloud-capable data boundaries configured"\n'
        '    if "warn" in statuses:\n',
        '            "deep-research-cloud-configured",\n'
        '            "nim-vendor-cloud-default-endpoint",\n'
        '            "server-cloud-engine-credential-present",\n'
        '        }\n'
        '    ):\n'
        '        return "cloud-capable data boundaries configured"\n'
        '    if "nim-custom-endpoint-configured" in finding_ids:\n'
        '        return "custom NIM endpoint requires data-boundary review"\n'
        '    if "warn" in statuses:\n',
        "verdict parity",
    )

    compile(text, str(AUDIT), "exec")
    AUDIT.write_text(text, encoding="utf-8")


def patch_docs() -> None:
    text = DOC.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '- cloud-capable model provider, engine, and default model settings\n',
        '- cloud-capable model provider, engine, and default model settings\n'
        '- cloud-engine auto-activation in `jarvis serve` from supported API credentials\n'
        '- NVIDIA NIM default-vendor versus custom-endpoint boundary semantics\n',
        "docs current checks",
    )
    text = replace_once(
        text,
        'Model identifiers that contain vendor names (for example `deepseek-r1` or\n'
        '`openai/gpt-oss`) are not treated as cloud-bound when their effective engine is\n'
        'explicitly local, such as Ollama.\n',
        'Model identifiers that contain vendor names (for example `deepseek-r1` or\n'
        '`openai/gpt-oss`) are not treated as cloud-bound when their effective engine is\n'
        'explicitly local, such as Ollama. NVIDIA NIM is endpoint-dependent: without\n'
        '`NIM_HOST` it uses NVIDIA\'s hosted API; when `NIM_HOST` is set, the scanner\n'
        'reports a custom endpoint with unknown locality without reading or printing the\n'
        'environment value.\n',
        "docs NIM semantics",
    )
    text = replace_once(
        text,
        'Also unset cloud and channel credentials from the process environment when they\n'
        'are not needed.\n',
        'Also unset cloud and channel credentials from the process environment when they\n'
        'are not needed. `jarvis serve` can automatically make cloud inference available\n'
        'when supported cloud-provider API credentials are present, so strict local-only\n'
        'checks treat those credentials as an active cloud-capable surface.\n',
        "docs strict cloud activation",
    )
    DOC.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    patch_audit()
    patch_docs()
