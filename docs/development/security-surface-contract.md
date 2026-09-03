# Runtime security-surface contract

OpenJarvis has multiple registries that can introduce data sources, stores, transformations, execution capabilities, or outbound sinks. A boundary scanner can only remain trustworthy if those registries cannot grow invisibly.

The security-surface manifest establishes a closure contract for registry-backed runtime surfaces. Every registry class must have an explicit accounting policy. Registries with per-key security semantics require every registered key to be either modeled or explicitly exempted. Registries whose security behavior is inherited from another primitive may use delegated semantics with a stated rationale.

## Current accounting

Inference engines are modeled. `ENGINE_ENDPOINT_SPECS` is the authoritative import-safe inventory for engine endpoint trust-boundary semantics, and engine-specific closure tests cover the data-driven compatible-engine registration table.

Existing per-key non-engine registry surfaces currently have explicit `legacy-exemption` entries. Those entries are migration debt, not assertions that the surfaces are local, safe, or fully understood. The baseline is intentionally enumerated key by key so a newly registered surface does not inherit an exemption automatically.

`ModelRegistry` uses delegated semantics. Model entries describe model identity and supported engines; endpoint transport is resolved by the selected engine, so endpoint trust-boundary semantics are owned by `EngineRegistry`.

## Enforcement

`tests/security/test_surface_manifest.py` parses registration sites statically. It does not import agent, channel, connector, engine, learning, mining, speech, or tool packages and does not probe endpoints. The tests enforce four invariants:

1. Every registry class has an explicit security accounting policy.
2. Every literal registration in a per-key registry is modeled or explicitly exempted.
3. Dynamic registration sites in per-key registries are explicitly accounted for.
4. Legacy exemptions cannot silently become stale, and modeled entries cannot also remain exempted.

Adding a new per-key runtime surface therefore requires a security decision in the same change. Prefer modeled boundary semantics. If the semantics are not yet available, add an explicit exemption and treat it as reviewable security debt. Dynamic registration requires an additional accounting entry and, when it expands into multiple runtime keys, a registry-specific closure test over those keys.

This contract covers registry-backed runtime surfaces. It does not claim that every non-registry code path is already modeled; direct runtime construction and configuration-driven sinks remain separate inventory work.