from pathlib import Path


def replace_all(path: str, old: str, new: str, expected: int) -> None:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise RuntimeError(f"{path}: expected {expected} matches, found {count}")
    file_path.write_text(text.replace(old, new), encoding="utf-8")


replace_all(
    "src/openjarvis/security/data_boundary_audit.py",
    "NIM_HOST is not set; NIM uses the NVIDIA-hosted default",
    "NIM_HOST is absent or empty; NIM uses the NVIDIA-hosted default",
    1,
)
replace_all(
    "src/openjarvis/security/data_boundary_audit.py",
    "knowledge.db exists; NIM_HOST is set; value was not ",
    "knowledge.db exists; NIM_HOST is non-empty; value was not ",
    1,
)
replace_all(
    "src/openjarvis/security/data_boundary_audit.py",
    "agent.context_from_memory = true; NIM_HOST is set; ",
    "agent.context_from_memory = true; NIM_HOST is non-empty; ",
    1,
)
replace_all(
    "src/openjarvis/security/data_boundary_audit.py",
    'evidence=f"{selected}; NIM_HOST is not set"',
    'evidence=f"{selected}; NIM_HOST is absent or empty"',
    1,
)

path = Path("tests/security/test_data_boundary_runtime_parity.py")
text = path.read_text(encoding="utf-8")
old = '''    assert findings["nim-vendor-cloud-default-endpoint"].status == "warn"\n    assert "nim-custom-endpoint-configured" not in findings\n\n\ndef test_knowledge_plus_default_nim_is_fail'''
new = '''    finding = findings["nim-vendor-cloud-default-endpoint"]\n    assert finding.status == "warn"\n    assert "NIM_HOST is absent or empty" in finding.evidence\n    assert "nim-custom-endpoint-configured" not in findings\n\n\ndef test_knowledge_plus_default_nim_is_fail'''
if text.count(old) != 1:
    raise RuntimeError("empty NIM host test anchor mismatch")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
