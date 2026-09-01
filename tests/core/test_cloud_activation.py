from __future__ import annotations

from openjarvis.core.cloud_activation import (
    SERVER_AUTO_CLOUD_ENGINE_ENV_VARS,
    active_server_cloud_credentials,
)


def test_server_cloud_activation_credential_set_is_exact():
    assert SERVER_AUTO_CLOUD_ENGINE_ENV_VARS == {
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
    }


def test_active_server_cloud_credentials_returns_names_only():
    environ = {
        "OPENROUTER_API_KEY": "canary-secret-value",
        "GOOGLE_API_KEY": "",
        "UNRELATED": "value",
    }

    active = active_server_cloud_credentials(environ)

    assert active == ("OPENROUTER_API_KEY",)
    assert "canary-secret-value" not in repr(active)
