"""Tests for `method_cfg.worker_pool` cell-config override.

Conductor and ToolOrchestra previously hardcoded a heterogeneous worker
pool (Opus + gpt-5-mini + optional local Qwen + optional web-search). The
override lets cells swap the pool composition without code changes.
Strict replace (not merge) by design — simpler reasoning at the cell-config
layer.

These tests touch only the construction site:
- override accepted + default replaced
- invalid entries raise at init, with the right error message format
- `$local` / `$cloud` substitution works
- absent override = legacy behavior (default pool intact)

We never exercise `_call_worker` here — that's the consumer logic and is
out of scope for this change.
"""

from __future__ import annotations

import pytest

from openjarvis.agents.hybrid.conductor import (
    ConductorAgent,
    _resolve_worker_pool as _resolve_conductor_pool,
)
from openjarvis.agents.hybrid.toolorchestra import (
    ToolOrchestraAgent,
    _resolve_worker_pool as _resolve_toolorch_pool,
)


# ---------------------------------------------------------------------------
# Common construction helpers
# ---------------------------------------------------------------------------


def _conductor(cfg: dict, *, local_model: str | None = None) -> ConductorAgent:
    return ConductorAgent(
        engine=None,
        model="claude-opus-4-7",
        local_model=local_model,
        local_endpoint="http://localhost:8001/v1" if local_model else None,
        cloud_endpoint="anthropic",
        cfg=cfg,
    )


def _toolorch(cfg: dict, *, local_model: str | None = None) -> ToolOrchestraAgent:
    return ToolOrchestraAgent(
        engine=None,
        model="claude-opus-4-7",
        local_model=local_model,
        local_endpoint="http://localhost:8001/v1" if local_model else None,
        cloud_endpoint="anthropic",
        cfg=cfg,
    )


# ---------------------------------------------------------------------------
# Valid override replaces the default pool
# ---------------------------------------------------------------------------


def test_conductor_worker_pool_override_replaces_default() -> None:
    pool = [
        {
            "id": 0,
            "name": "cheap",
            "endpoint": "openai",
            "model": "gpt-5-mini",
            "description": "cheap one",
        },
        {
            "id": 1,
            "name": "strong",
            "endpoint": "anthropic",
            "model": "claude-opus-4-7",
            "description": "strong one",
        },
    ]
    agent = _conductor({"worker_pool": pool})
    resolved = _resolve_conductor_pool(
        agent._cfg, agent._local_model, agent._local_endpoint, agent._cloud_model,
    )
    assert [w["name"] for w in resolved] == ["cheap", "strong"]
    assert [w["model"] for w in resolved] == ["gpt-5-mini", "claude-opus-4-7"]
    # Default pool would have included "frontier-anthropic" / "frontier-openai-mini"
    # by name; the override must NOT carry those over.
    assert "frontier-anthropic" not in {w["name"] for w in resolved}


def test_toolorch_worker_pool_override_replaces_default() -> None:
    pool = [
        {
            "id": 0,
            "name": "search",
            "type": "anthropic-web-search",
            # model omitted on purpose — search type allows it
        },
        {
            "id": 1,
            "name": "solver",
            "type": "openai",
            "model": "gpt-5-mini",
        },
    ]
    agent = _toolorch(pool=None, cfg=None) if False else _toolorch({"worker_pool": pool})
    resolved = _resolve_toolorch_pool(
        agent._cfg, agent._local_model, agent._local_endpoint, agent._cloud_model,
    )
    assert [w["name"] for w in resolved] == ["search", "solver"]
    # Search entry got the default web-search model filled in.
    assert resolved[0]["model"] == "claude-haiku-4-5"
    # Default pool's "frontier-anthropic" / "frontier-openai-mini" should be gone.
    assert "frontier-anthropic" not in {w["name"] for w in resolved}


# ---------------------------------------------------------------------------
# Invalid entries raise at agent init with the right message
# ---------------------------------------------------------------------------


def test_conductor_invalid_entry_raises_at_init() -> None:
    bad_pool = [
        {
            "id": 0,
            "name": "broken",
            "endpoint": "openai",
            "model": "not-a-real-model",
        },
    ]
    with pytest.raises(ValueError, match=r"Invalid worker_pool entry \[0\]: model 'not-a-real-model'"):
        _conductor({"worker_pool": bad_pool})


def test_toolorch_invalid_type_raises_at_init() -> None:
    bad_pool = [
        {
            "id": 0,
            "name": "broken",
            "type": "imaginary-endpoint",
            "model": "gpt-5-mini",
        },
    ]
    with pytest.raises(ValueError, match=r"Invalid worker_pool entry \[0\]: 'type' must be one of"):
        _toolorch({"worker_pool": bad_pool})


def test_only_search_workers_rejected() -> None:
    # Toolorchestra: pool with ONLY web-search must fail — no solver.
    bad_pool = [
        {"id": 0, "name": "only-search", "type": "anthropic-web-search"},
    ]
    with pytest.raises(
        ValueError, match=r"at least one non-search worker"
    ):
        _toolorch({"worker_pool": bad_pool})


def test_empty_pool_rejected() -> None:
    with pytest.raises(ValueError, match=r"non-empty list"):
        _conductor({"worker_pool": []})
    with pytest.raises(ValueError, match=r"non-empty list"):
        _toolorch({"worker_pool": []})


def test_duplicate_ids_rejected() -> None:
    pool = [
        {"id": 0, "name": "a", "endpoint": "openai", "model": "gpt-5-mini"},
        {"id": 0, "name": "b", "endpoint": "anthropic", "model": "claude-opus-4-7"},
    ]
    with pytest.raises(ValueError, match=r"Invalid worker_pool entry \[0\]: duplicate id"):
        _conductor({"worker_pool": pool})


# ---------------------------------------------------------------------------
# $local / $cloud substitution
# ---------------------------------------------------------------------------


def test_conductor_local_cloud_substitution() -> None:
    pool = [
        {
            "id": 0,
            "name": "local",
            "endpoint": "vllm",
            "model": "$local",
        },
        {
            "id": 1,
            "name": "cloud",
            "endpoint": "anthropic",
            "model": "$cloud",
        },
    ]
    agent = _conductor(
        {"worker_pool": pool},
        local_model="Qwen/Qwen3.5-9B",
    )
    resolved = _resolve_conductor_pool(
        agent._cfg, agent._local_model, agent._local_endpoint, agent._cloud_model,
    )
    assert resolved[0]["model"] == "Qwen/Qwen3.5-9B"
    assert resolved[1]["model"] == "claude-opus-4-7"
    # vllm worker got the local endpoint inherited as base_url default.
    assert resolved[0]["base_url"] == "http://localhost:8001/v1"


def test_toolorch_local_cloud_substitution_with_angle_brackets() -> None:
    # Accept both `$local` / `$cloud` and `<local>` / `<cloud>` syntaxes.
    pool = [
        {"id": 0, "name": "lo", "type": "vllm", "model": "<local>"},
        {"id": 1, "name": "hi", "type": "anthropic", "model": "<cloud>"},
    ]
    agent = _toolorch(
        {"worker_pool": pool},
        local_model="google/gemma-4-26B-A4B-it",
    )
    resolved = _resolve_toolorch_pool(
        agent._cfg, agent._local_model, agent._local_endpoint, agent._cloud_model,
    )
    assert resolved[0]["model"] == "google/gemma-4-26B-A4B-it"
    assert resolved[1]["model"] == "claude-opus-4-7"


def test_local_substitution_without_local_model_raises() -> None:
    pool = [
        {"id": 0, "name": "lo", "endpoint": "vllm", "model": "$local"},
    ]
    with pytest.raises(ValueError, match=r"requires a local_model"):
        _conductor({"worker_pool": pool})


# ---------------------------------------------------------------------------
# Absent override = default behavior unchanged
# ---------------------------------------------------------------------------


def test_no_override_uses_default_pool_conductor() -> None:
    # No `worker_pool` key — resolver returns the default pool, which is the
    # paper-faithful 7-worker composition (arXiv 2512.04388): Gemini-2.5-Pro,
    # Claude Sonnet-4, GPT-5, plus four OpenRouter-routed open-weights
    # workers (DeepSeek-R1-Distill-Qwen-32B, Gemma3-27B-it, Qwen3-32B,
    # Qwen3-32B-thinking).
    agent = _conductor({})
    resolved = _resolve_conductor_pool(
        agent._cfg, agent._local_model, agent._local_endpoint, agent._cloud_model,
    )
    names = {w["name"] for w in resolved}
    assert names == {
        "gemini-pro",
        "claude-sonnet-4",
        "gpt-5",
        "deepseek-r1-distill-qwen-32b",
        "gemma3-27b-it",
        "qwen3-32b",
        "qwen3-32b-thinking",
    }


def test_no_override_uses_default_pool_toolorch() -> None:
    agent = _toolorch({})
    resolved = _resolve_toolorch_pool(
        agent._cfg, agent._local_model, agent._local_endpoint, agent._cloud_model,
    )
    names = {w["name"] for w in resolved}
    # Default toolorch pool: web-search + frontier-anthropic + frontier-openai-mini.
    assert names == {"web-search", "frontier-anthropic", "frontier-openai-mini"}
