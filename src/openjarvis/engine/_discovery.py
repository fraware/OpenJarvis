"""Engine discovery — probe running engines and aggregate available models."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Tuple

from openjarvis.core.config import JarvisConfig
from openjarvis.core.inference_boundaries import (
    ENGINE_ENDPOINT_SPECS,
    EndpointBoundary,
    boundary_from_engine_instance,
    resolve_engine_boundary,
    same_host_egress_class,
)
from openjarvis.core.registry import EngineRegistry
from openjarvis.engine._base import InferenceEngine

logger = logging.getLogger(__name__)


def _configured_host_argument(key: str, config: JarvisConfig) -> str | None:
    """Return the non-empty config host passed explicitly to an engine.

    Endpoint metadata owns the mapping from engine keys to config paths so
    discovery and boundary classification cannot drift through separate host
    tables.
    """

    spec = ENGINE_ENDPOINT_SPECS.get(key)
    if spec is None or spec.config_path is None:
        return None
    current: Any = config
    for part in spec.config_path.split("."):
        current = getattr(current, part, None)
        if current is None:
            return None
    host = str(current or "").strip()
    return host or None


def _make_engine(key: str, config: JarvisConfig) -> InferenceEngine:
    """Instantiate a registered engine with the appropriate config host."""
    cls = EngineRegistry.get(key)

    # LiteLLM cannot enumerate every model supported by every provider. Its
    # list_models() contract therefore advertises the configured default
    # model, which must be supplied when discovery constructs the engine.
    if key == "litellm":
        return cls(default_model=config.intelligence.default_model or None)

    # gemma_cpp: pass config fields instead of host
    if key == "gemma_cpp":
        cfg = config.engine.gemma_cpp
        return cls(
            model_path=cfg.model_path or None,
            tokenizer_path=cfg.tokenizer_path or None,
            model_type=cfg.model_type or None,
            num_threads=cfg.num_threads,
        )

    # afm: in-process engine, configured by behaviour rather than a host
    if key == "afm":
        cfg = config.engine.afm
        return cls(
            instructions=cfg.instructions,
            use_case=cfg.use_case,
            guardrails=cfg.guardrails,
            sampling=cfg.sampling,
        )

    host = _configured_host_argument(key, config)
    if host is not None:
        return cls(host=host)
    return cls()


def _maybe_register_mining_sidecar_engine() -> None:
    """If a mining sidecar exists with a ``vllm_endpoint``, register a derived
    vLLM engine class pointing at it. Idempotent. Quiet on error.

    The trigger is the *shape* of the sidecar (presence of ``vllm_endpoint``),
    not the value of its ``provider`` field — this leaves room for future
    non-engine-replacing providers (e.g., a hypothetical cpu-pearl) whose
    sidecars don't include ``vllm_endpoint``.
    """
    try:
        from openjarvis.mining import Sidecar
        from openjarvis.mining._constants import SIDECAR_PATH
    except ImportError:
        return

    if EngineRegistry.contains("vllm-pearl-mining"):
        return  # idempotent

    payload = Sidecar.read(SIDECAR_PATH)
    if payload is None:
        return

    endpoint = payload.get("vllm_endpoint")
    model = payload.get("model")
    if not endpoint or not model:
        return  # data-driven gate: no vllm_endpoint → don't register

    from openjarvis.engine._openai_compat import _OpenAICompatibleEngine

    # Strip a trailing "/v1" path segment so _default_host is the bare
    # base URL and _api_prefix="/v1" combines correctly in request paths.
    api_prefix = "/v1"
    base_url = endpoint.rstrip("/")
    if base_url.endswith(api_prefix):
        base_url = base_url[: -len(api_prefix)]

    _cls = type(
        "VllmPearlMiningEngine",
        (_OpenAICompatibleEngine,),
        {
            "engine_id": "vllm-pearl-mining",
            "_default_host": base_url,
            "_api_prefix": api_prefix,
        },
    )
    EngineRegistry.register_value("vllm-pearl-mining", _cls)


def discover_engines(config: JarvisConfig) -> List[Tuple[str, InferenceEngine]]:
    """Probe registered engines and return ``[(key, instance)]`` for healthy ones.

    Results are sorted with the config default engine first.
    """
    _maybe_register_mining_sidecar_engine()

    # Probe engines concurrently: each health() does a blocking network
    # check with its own timeout, so a serial loop costs the SUM of all
    # probe timeouts (dead localhost ports especially). Running them in
    # threads collapses that to roughly the slowest single probe. The
    # healthy.sort() below normalizes order, so completion order is
    # irrelevant and the result is identical to the serial version (#263).
    keys = list(EngineRegistry.keys())

    def _probe(key: str) -> Tuple[str, InferenceEngine] | None:
        try:
            engine = _make_engine(key, config)
            if engine.health():
                return (key, engine)
        except Exception as exc:
            logger.debug("Engine %r failed during discovery: %s", key, exc)
        return None

    healthy: List[Tuple[str, InferenceEngine]] = []
    if keys:
        with ThreadPoolExecutor(max_workers=len(keys)) as pool:
            for result in pool.map(_probe, keys):
                if result is not None:
                    healthy.append(result)

    default_key = config.engine.default

    def sort_key(item: Tuple[str, Any]) -> Tuple[int, str]:
        return (0 if item[0] == default_key else 1, item[0])

    healthy.sort(key=sort_key)
    return healthy


def discover_models(
    engines: List[Tuple[str, InferenceEngine]],
) -> Dict[str, List[str]]:
    """Call ``list_models()`` on each engine and return a dict."""
    result: Dict[str, List[str]] = {}
    for key, engine in engines:
        try:
            result[key] = engine.list_models()
        except Exception as exc:
            logger.debug("Failed to list models for engine %r: %s", key, exc)
            result[key] = []
    return result


def _boundary_transition_suffix(
    source: EndpointBoundary,
    target: EndpointBoundary,
) -> str:
    if source == target:
        return ""
    if source is EndpointBoundary.UNKNOWN or target is EndpointBoundary.UNKNOWN:
        return f" with endpoint boundary {source.value} -> {target.value}"
    if source.leaves_local_host != target.leaves_local_host:
        return (
            f" across the local-host trust boundary ({source.value} -> {target.value})"
        )
    return f" across endpoint boundary classes ({source.value} -> {target.value})"


def get_engine(
    config: JarvisConfig,
    engine_key: str | None = None,
    model: str | None = None,
) -> Tuple[str, InferenceEngine] | None:
    """Get a specific engine by key, or the default with a named fallback.

    An explicit ``engine_key`` is authoritative and is never silently
    substituted. Default-engine fallback first prefers the same endpoint trust
    boundary, then the same local-host egress class, and names any boundary
    transition in the fallback warning.

    When *model* is given, an engine is selected only if it can actually
    serve that model (``engine.can_serve(model)``). This stops the cloud
    fallback from being chosen — when the local engine is down — for a model
    whose provider client is missing, which otherwise surfaces as a confusing
    "OpenAI client not available" instead of a helpful "start your local
    engine" message (see #532). When *model* is ``None`` selection stays
    model-agnostic (unchanged behaviour).

    Returns ``(key, engine_instance)`` or ``None`` if no engine is available.
    """

    def _usable(engine: InferenceEngine) -> bool:
        return engine.health() and (model is None or engine.can_serve(model))

    if engine_key:
        if not EngineRegistry.contains(engine_key):
            logger.warning("Requested engine %r is not registered", engine_key)
            return None
        try:
            engine = _make_engine(engine_key, config)
            if _usable(engine):
                return (engine_key, engine)
        except Exception as exc:
            logger.debug("Engine %r health check failed: %s", engine_key, exc)
        logger.warning(
            "Requested engine %r is unavailable%s; no substitute was selected",
            engine_key,
            f" for model {model!r}" if model else "",
        )
        return None

    default_key = config.engine.default
    default_boundary = resolve_engine_boundary(default_key, config).boundary
    if default_key and EngineRegistry.contains(default_key):
        try:
            engine = _make_engine(default_key, config)
            default_boundary = boundary_from_engine_instance(default_key, engine)
            if _usable(engine):
                return (default_key, engine)
        except Exception as exc:
            logger.debug("Engine %r health check failed: %s", default_key, exc)

    candidates = [
        (key, engine)
        for key, engine in discover_engines(config)
        if key != default_key and (model is None or engine.can_serve(model))
    ]
    if not candidates:
        return None

    candidate_boundaries = [
        (candidate, boundary_from_engine_instance(candidate[0], candidate[1]))
        for candidate in candidates
    ]
    chosen: Tuple[str, InferenceEngine] | None = None
    chosen_boundary = EndpointBoundary.UNKNOWN

    if default_boundary is not EndpointBoundary.UNKNOWN:
        exact = next(
            (
                item
                for item, boundary in candidate_boundaries
                if boundary == default_boundary
            ),
            None,
        )
        if exact is not None:
            chosen = exact
            chosen_boundary = default_boundary
        else:
            same_egress = next(
                (
                    (item, boundary)
                    for item, boundary in candidate_boundaries
                    if same_host_egress_class(default_boundary, boundary)
                ),
                None,
            )
            if same_egress is not None:
                chosen, chosen_boundary = same_egress

    if chosen is None:
        chosen, chosen_boundary = candidate_boundaries[0]

    boundary = _boundary_transition_suffix(default_boundary, chosen_boundary)
    logger.warning(
        "Default engine %r is unavailable; using %r%s",
        default_key,
        chosen[0],
        boundary,
    )
    return chosen


__all__ = ["discover_engines", "discover_models", "get_engine"]
