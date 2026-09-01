"""Import-safe metadata for server cloud-engine auto-activation.

The server treats the presence of any credential in
``SERVER_AUTO_CLOUD_ENGINE_ENV_VARS`` as a signal to prepare its cloud inference
engine alongside the selected primary engine. This module exposes only
credential names: values are inspected for truthiness but are never returned or
emitted.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

SERVER_AUTO_CLOUD_ENGINE_ENV_VARS = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
    }
)


def active_server_cloud_credentials(
    environ: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Return sorted names of credentials that can activate server cloud routing."""

    environment = os.environ if environ is None else environ
    return tuple(
        sorted(
            name for name in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS if environment.get(name)
        )
    )
