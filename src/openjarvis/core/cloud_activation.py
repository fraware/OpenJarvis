"""Pure helpers for credential-driven server cloud-engine activation.

`jarvis serve` conditionally adds a cloud engine when any supported provider
credential is present. Security diagnostics consume the same declaration so the
runtime and the data-boundary scan cannot silently drift on this capability.
Only variable names and presence are inspected; credential values are never
returned.
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
    """Return names of credentials that activate the server cloud engine.

    The returned tuple is sorted for deterministic diagnostics. Credential
    values are used only for truthiness, and are never returned or emitted.
    """

    source = os.environ if environ is None else environ
    return tuple(
        sorted(name for name in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS if source.get(name))
    )


__all__ = [
    "SERVER_AUTO_CLOUD_ENGINE_ENV_VARS",
    "active_server_cloud_credentials",
]
