from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f"anchor missing in {path}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    """    if root_path is not None:\n        _audit_local_stores(root_path, builder, config=active_config)\n        _audit_connector_credentials(root_path, builder)\n""",
    """    if root_path is not None:\n        _audit_local_stores(root_path, builder, config=active_config)\n        _audit_stored_credentials_cloud_activation(root_path, builder)\n        _audit_connector_credentials(root_path, builder)\n""",
)

replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    """\n\ndef _audit_connector_credentials(root: Path, builder: _FindingBuilder) -> None:\n""",
    """\n\ndef _audit_stored_credentials_cloud_activation(\n    root: Path,\n    builder: _FindingBuilder,\n) -> None:\n    credential_store = root / \"credentials.toml\"\n    if not credential_store.exists():\n        return\n    builder.add(\n        finding_id=\"stored-credentials-cloud-activation-unknown\",\n        status=\"warn\",\n        title=\"Stored credentials cannot be classified for server cloud activation\",\n        potential_data_path=(\n            \"credentials.toml -> server credential injection -> possible cloud engine\"\n        ),\n        evidence=(\n            \"credentials.toml exists; credential names and values were not inspected\"\n        ),\n        recommendation=(\n            \"Review or remove unneeded stored credentials before strict local-only \"\n            \"server use.\"\n        ),\n        location=\"credentials.toml\",\n        absolute_location=str(credential_store),\n    )\n\n\ndef _audit_connector_credentials(root: Path, builder: _FindingBuilder) -> None:\n""",
)

replace_once(
    "src/openjarvis/security/data_boundary_audit.py",
    """    if \"nim-custom-endpoint-configured\" in finding_ids:\n        return \"custom NIM endpoint requires data-boundary review\"\n    if \"warn\" in statuses:\n""",
    """    if \"nim-custom-endpoint-configured\" in finding_ids:\n        return \"custom NIM endpoint requires data-boundary review\"\n    if \"stored-credentials-cloud-activation-unknown\" in finding_ids:\n        return \"stored credentials require server cloud-boundary review\"\n    if \"warn\" in statuses:\n""",
)

replace_once(
    "docs/user-guide/data-boundary-scan.md",
    """- API-key and other runtime credential environment variables (presence only)\n- a scope note for frontend credential storage when cloud/API-key surfaces exist\n""",
    """- API-key and other runtime credential environment variables (presence only)\n- persisted credential-store uncertainty for server cloud activation, without reading the store\n- a scope note for frontend credential storage when cloud/API-key surfaces exist\n""",
)

replace_once(
    "docs/user-guide/data-boundary-scan.md",
    """Absolute paths and connector file basenames are redacted by default so JSON\nreports can be pasted into issues without revealing local usernames, mount\npoints, or account labels. Use `--show-paths` only for local debugging.\n""",
    """Absolute paths and connector file basenames are redacted by default so JSON\nreports can be pasted into issues without revealing local usernames, mount\npoints, or account labels. Use `--show-paths` only for local debugging.\n\nBecause `jarvis serve` loads persisted runtime credentials before engine\ndiscovery, a present `credentials.toml` produces an uncertainty warning. The\nscan does not read credential names or values to decide which routes the store\ncould enable.\n""",
)

replace_once(
    "tests/security/test_data_boundary_runtime_parity.py",
    """\ndef test_nim_api_key_is_specialized_and_redacted_when_nim_active(tmp_path, monkeypatch):\n""",
    """\ndef test_stored_credentials_emit_server_cloud_uncertainty(tmp_path, monkeypatch):\n    _clear_boundary_env(monkeypatch)\n    config = _low_noise_config()\n    canary = \"canary-stored-credential-content\"\n    (tmp_path / \"credentials.toml\").write_text(canary, encoding=\"utf-8\")\n\n    report = build_data_boundary_report(config, tmp_path)\n    finding = _findings(report)[\"stored-credentials-cloud-activation-unknown\"]\n\n    assert finding.status == \"warn\"\n    assert finding.location == \"credentials.toml\"\n    assert canary not in str(report.to_dict(show_paths=True))\n    assert report.verdict == \"stored credentials require server cloud-boundary review\"\n\n\ndef test_nim_api_key_is_specialized_and_redacted_when_nim_active(tmp_path, monkeypatch):\n""",
)
