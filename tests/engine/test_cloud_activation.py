from __future__ import annotations

from openjarvis.engine.cloud_activation import (
    SERVER_AUTO_CLOUD_ENGINE_ENV_VARS,
    active_server_cloud_credentials,
)


def test_server_cloud_activation_keys_match_supported_cloud_providers():
    assert SERVER_AUTO_CLOUD_ENGINE_ENV_VARS == {
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
    }


def test_active_server_cloud_credentials_reports_names_only():
    environ = {
        "OPENAI_API_KEY": "canary-openai-secret",
        "ANTHROPIC_API_KEY": "canary-anthropic-secret",
        "UNRELATED": "value",
    }

    active = active_server_cloud_credentials(environ)

    assert active == ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")
    assert "canary-openai-secret" not in str(active)
    assert "canary-anthropic-secret" not in str(active)
