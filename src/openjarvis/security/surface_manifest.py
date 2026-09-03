"""Import-safe security-surface accounting for runtime registries.

Every per-key runtime registration is required to have modeled security
semantics or an explicit legacy exemption. The legacy baseline is
intentionally enumerated so additions cannot inherit an exemption by
accident. Model catalog entries use delegated semantics because endpoint
egress is owned by the selected inference engine.
"""

from __future__ import annotations

from typing import Final, Mapping

from openjarvis.core.inference_boundaries import ENGINE_ENDPOINT_SPECS

PER_KEY_SECURITY_REGISTRIES: Final[frozenset[str]] = frozenset(
    {
        "AgentRegistry",
        "BenchmarkRegistry",
        "ChannelRegistry",
        "CompressionRegistry",
        "ConnectorRegistry",
        "EngineRegistry",
        "FactStoreRegistry",
        "LearningRegistry",
        "MemoryRegistry",
        "MinerRegistry",
        "RouterPolicyRegistry",
        "SkillRegistry",
        "SpeechRegistry",
        "TTSRegistry",
        "ToolRegistry",
    }
)

# Model IDs are catalog metadata. They do not resolve transport on their
# own; the selected inference engine owns endpoint trust-boundary semantics.
DELEGATED_SECURITY_REGISTRIES: Final[Mapping[str, str]] = {
    "ModelRegistry": "endpoint boundary delegated to EngineRegistry",
}

MODELED_SURFACE_KEYS: Final[Mapping[str, frozenset[str]]] = {
    "EngineRegistry": frozenset(ENGINE_ENDPOINT_SPECS),
}

# Existing non-engine surfaces predate the boundary metadata contract. Each
# key is listed explicitly; adding a new key requires either modeled semantics
# or a deliberate exemption update reviewed as a security change.
LEGACY_UNMODELED_SURFACE_EXEMPTIONS: Final[Mapping[str, frozenset[str]]] = {
    "AgentRegistry": frozenset(
        {
            "advisors",
            "archon",
            "baseline_cloud",
            "baseline_local",
            "claude_code",
            "conductor",
            "deep_research",
            "mini_swe_agent",
            "minions",
            "monitor_operative",
            "morning_digest",
            "native_openhands",
            "native_react",
            "opencode",
            "openhands",
            "operative",
            "orchestrator",
            "proactive",
            "react",
            "rlm",
            "simple",
            "skillorchestra",
            "toolorchestra",
        }
    ),
    "BenchmarkRegistry": frozenset(
        {
            "energy",
            "latency",
            "throughput",
        }
    ),
    "ChannelRegistry": frozenset(
        {
            "bluebubbles",
            "discord",
            "email",
            "feishu",
            "gmail",
            "google_chat",
            "irc",
            "line",
            "mastodon",
            "matrix",
            "mattermost",
            "messenger",
            "nostr",
            "reddit",
            "rocketchat",
            "sendblue",
            "signal",
            "slack",
            "teams",
            "telegram",
            "twilio",
            "twitch",
            "twitter",
            "viber",
            "webchat",
            "webhook",
            "whatsapp",
            "whatsapp_baileys",
            "xmpp",
            "zulip",
        }
    ),
    "CompressionRegistry": frozenset(
        {
            "model_summarization",
            "rule_based_precompression",
            "session_consolidation",
            "tiered_summaries",
        }
    ),
    "ConnectorRegistry": frozenset(
        {
            "apple_calendar",
            "apple_contacts",
            "apple_health",
            "apple_music",
            "apple_notes",
            "dropbox",
            "gcalendar",
            "gcontacts",
            "gdrive",
            "github_notifications",
            "gmail",
            "gmail_imap",
            "google_tasks",
            "granola",
            "hackernews",
            "imap",
            "imessage",
            "news_rss",
            "notion",
            "obsidian",
            "oura",
            "outlook",
            "slack",
            "spotify",
            "strava",
            "weather",
            "whatsapp",
        }
    ),
    "FactStoreRegistry": frozenset(
        {
            "local",
        }
    ),
    "LearningRegistry": frozenset(
        {
            "ace",
            "dspy",
            "gepa",
            "grpo",
            "orchestrator_grpo",
            "orchestrator_sft",
            "sft",
        }
    ),
    "MemoryRegistry": frozenset(
        {
            "bm25",
            "colbert",
            "dense",
            "faiss",
            "hybrid",
            "knowledge",
            "knowledge_graph",
            "sqlite",
        }
    ),
    "MinerRegistry": frozenset(
        {
            "apple-mps-pearl",
            "cpu-pearl",
            "vllm-pearl",
        }
    ),
    "RouterPolicyRegistry": frozenset(
        {
            "heuristic",
            "learned",
        }
    ),
    "SpeechRegistry": frozenset(
        {
            "deepgram",
            "faster-whisper",
            "openai",
        }
    ),
    "TTSRegistry": frozenset(
        {
            "cartesia",
            "kokoro",
            "openai_tts",
        }
    ),
    "ToolRegistry": frozenset(
        {
            "agent_kill",
            "agent_list",
            "agent_send",
            "agent_spawn",
            "apply_patch",
            "audio_transcribe",
            "browser_axtree",
            "browser_click",
            "browser_extract",
            "browser_navigate",
            "browser_screenshot",
            "browser_type",
            "calculator",
            "calendar_search",
            "calendar_upcoming",
            "cancel_scheduled_task",
            "channel_list",
            "channel_send",
            "channel_status",
            "check_permission",
            "code_interpreter",
            "code_interpreter_docker",
            "db_query",
            "digest_collect",
            "docker_shell_exec",
            "execute_pending_actions",
            "file_read",
            "file_write",
            "get_pending_actions",
            "git_commit",
            "git_diff",
            "git_log",
            "git_status",
            "http_request",
            "image_generate",
            "kg_add_entity",
            "kg_add_relation",
            "kg_neighbors",
            "kg_query",
            "knowledge_search",
            "knowledge_sql",
            "list_scheduled_tasks",
            "llm",
            "memory_index",
            "memory_manage",
            "memory_retrieve",
            "memory_search",
            "memory_store",
            "pause_scheduled_task",
            "pdf_extract",
            "queue_action",
            "record_decision",
            "repl",
            "resume_scheduled_task",
            "retrieval",
            "scan_chunks",
            "schedule_task",
            "shell_exec",
            "skill_manage",
            "text_to_speech",
            "think",
            "user_profile_manage",
            "web_search",
        }
    ),
}

# Dynamic registration must be visible to the closure tests. The data-driven
# engine table is independently checked against ENGINE_ENDPOINT_SPECS.
ACCOUNTED_DYNAMIC_REGISTRATION_SITES: Final[Mapping[tuple[str, str, str], str]] = {
    (
        "EngineRegistry",
        "src/openjarvis/engine/openai_compat_engines.py",
        "_key",
    ): "keys closed against ENGINE_ENDPOINT_SPECS",
}


def surface_disposition(registry: str, key: str) -> str | None:
    """Return the accounting disposition for one registry surface."""

    if registry in DELEGATED_SECURITY_REGISTRIES:
        return "delegated"
    if key in MODELED_SURFACE_KEYS.get(registry, frozenset()):
        return "modeled"
    if key in LEGACY_UNMODELED_SURFACE_EXEMPTIONS.get(registry, frozenset()):
        return "legacy-exemption"
    return None


__all__ = [
    "ACCOUNTED_DYNAMIC_REGISTRATION_SITES",
    "DELEGATED_SECURITY_REGISTRIES",
    "LEGACY_UNMODELED_SURFACE_EXEMPTIONS",
    "MODELED_SURFACE_KEYS",
    "PER_KEY_SECURITY_REGISTRIES",
    "surface_disposition",
]
