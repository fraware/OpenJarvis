from __future__ import annotations

from openjarvis.cli._bootstrap import _KEY_TO_PROVIDER
from openjarvis.core.credentials import (
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


def test_server_cloud_activation_matches_bootstrap_detection():
    bootstrap_keys = frozenset(name for name, _provider in _KEY_TO_PROVIDER)
    assert SERVER_AUTO_CLOUD_ENGINE_ENV_VARS == bootstrap_keys
