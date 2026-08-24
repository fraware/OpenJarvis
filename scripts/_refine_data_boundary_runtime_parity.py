"""Refine runtime-parity changes with a shared activation source of truth.

Temporary branch-local helper. Removed before opening the pull request.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "src/openjarvis/security/data_boundary_audit.py"
SERVE = ROOT / "src/openjarvis/cli/serve.py"
TEST = ROOT / "tests/security/test_data_boundary_runtime_parity.py"
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
        "from openjarvis.core.credentials import TOOL_CREDENTIALS\n",
        "from openjarvis.core.credentials import TOOL_CREDENTIALS\n"
        "from openjarvis.engine.cloud_activation import (\n"
        "    SERVER_AUTO_CLOUD_ENGINE_ENV_VARS,\n"
        "    active_server_cloud_credentials,\n"
        ")\n",
        "shared activation import",
    )

    local_constant = '''\n# `jarvis serve` automatically constructs a cloud engine when any of
# these credentials are present. Keep this explicit until runtime and
# diagnostics share one capability descriptor (follow-up architecture).
SERVER_AUTO_CLOUD_ENGINE_ENV_VARS = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
    }
)
'''
    text = replace_once(
        text,
        local_constant,
        "",
        "remove duplicated activation declaration",
    )

    text = replace_once(
        text,
        '''    return sorted(
        name for name in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS if os.environ.get(name)
    )
''',
        "    return list(active_server_cloud_credentials())\n",
        "shared activation helper use",
    )

    text = replace_once(
        text,
        '''    server_cloud_envs = _server_auto_cloud_envs()
    nim_vendor_cloud = _nim_uses_default_vendor_host(engine)
    nim_custom_host = _nim_uses_custom_host(engine)
    cloud_target = (
        _target_is_cloud(engine, model)
        or nim_vendor_cloud
        or bool(server_cloud_envs)
    )
''',
        '''    server_cloud_envs = _server_auto_cloud_envs()
    explicit_deep_engine = str(_get(config, "deep_research.engine", "") or "").strip()
    server_cloud_possible = bool(server_cloud_envs) and not explicit_deep_engine
    nim_vendor_cloud = _nim_uses_default_vendor_host(engine)
    nim_custom_host = _nim_uses_custom_host(engine)
    cloud_target = (
        _target_is_cloud(engine, model)
        or nim_vendor_cloud
        or server_cloud_possible
    )
''',
        "explicit Deep Research engine precedence",
    )
    text = replace_once(
        text,
        "        if server_cloud_envs:\n",
        "        if server_cloud_possible:\n",
        "knowledge server cloud evidence condition",
    )

    compile(text, str(AUDIT), "exec")
    AUDIT.write_text(text, encoding="utf-8")


def patch_serve() -> None:
    text = SERVE.read_text(encoding="utf-8")
    old = '''    # If cloud API keys are set, prepare a cloud engine. We build the
    # MultiEngine after local discovery so healthy local fallbacks such as
    # Ollama stay visible even when the configured preferred engine is MLX.
    import os

    cloud_engine = None
    _has_cloud = (
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or os.environ.get("GOOGLE_API_KEY")
        or os.environ.get("OPENROUTER_API_KEY")
    )
'''
    new = '''    # If cloud API keys are set, prepare a cloud engine. We build the
    # MultiEngine after local discovery so healthy local fallbacks such as
    # Ollama stay visible even when the configured preferred engine is MLX.
    from openjarvis.engine.cloud_activation import active_server_cloud_credentials

    cloud_engine = None
    _has_cloud = bool(active_server_cloud_credentials())
'''
    text = replace_once(text, old, new, "serve activation source of truth")
    compile(text, str(SERVE), "exec")
    SERVE.write_text(text, encoding="utf-8")


def patch_test() -> None:
    text = TEST.read_text(encoding="utf-8")
    anchor = '''def test_knowledge_plus_custom_nim_endpoint_is_warn(tmp_path, monkeypatch):
'''
    addition = '''def test_explicit_local_deep_research_engine_overrides_server_cloud_capability(
    tmp_path, monkeypatch
):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.deep_research.engine = "ollama"
    monkeypatch.setenv("OPENAI_API_KEY", "canary-openai-secret")
    (tmp_path / "knowledge.db").write_text("", encoding="utf-8")

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert "knowledge-chunks-to-cloud-risk" not in findings
    assert findings["server-cloud-engine-credential-present"].status == "warn"


'''
    text = replace_once(text, anchor, addition + anchor, "explicit local DR test")
    compile(text, str(TEST), "exec")
    TEST.write_text(text, encoding="utf-8")


def patch_docs() -> None:
    text = DOC.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "- cloud-engine auto-activation in `jarvis serve` from supported API credentials\n",
        "- cloud-engine auto-activation in `jarvis serve` from a shared credential declaration\n",
        "docs shared activation wording",
    )
    text = replace_once(
        text,
        "checks treat those credentials as an active cloud-capable surface.\n",
        "checks treat those credentials as an active cloud-capable surface. An explicit\n"
        "`deep_research.engine` remains authoritative for the static Deep Research\n"
        "composition check.\n",
        "docs explicit DR precedence",
    )
    DOC.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    patch_audit()
    patch_serve()
    patch_test()
    patch_docs()
