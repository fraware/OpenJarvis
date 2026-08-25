"""Prepare the clean runtime-parity candidate from the staging branch.

This helper is staging-only and removes itself after applying the guarded edits.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "src/openjarvis/security/data_boundary_audit.py"
SERVE = ROOT / "src/openjarvis/cli/serve.py"
CREDENTIALS = ROOT / "src/openjarvis/core/credentials.py"
CORE_TEST = ROOT / "tests/core/test_cloud_activation.py"
SECURITY_TEST = ROOT / "tests/security/test_data_boundary_runtime_parity.py"
DOCS = ROOT / "docs/user-guide/data-boundary-scan.md"
WORKFLOW = ROOT / ".github/workflows/_finalize-data-boundary-runtime-parity.yml"
SELF = Path(__file__)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def replace_region(
    text: str,
    start_marker: str,
    end_marker: str,
    replacement: str,
    label: str,
) -> str:
    start = text.find(start_marker)
    if start < 0:
        raise RuntimeError(f"{label}: start marker not found")
    end = text.find(end_marker, start + len(start_marker))
    if end < 0:
        raise RuntimeError(f"{label}: end marker not found")
    return text[:start] + replacement.rstrip() + "\n\n" + text[end:]


def patch_credentials() -> None:
    text = CREDENTIALS.read_text(encoding="utf-8")
    if "from collections.abc import Mapping\n" not in text:
        text = replace_once(
            text,
            "from __future__ import annotations\n\nimport logging\n",
            "from __future__ import annotations\n\nfrom collections.abc import Mapping\n\nimport logging\n",
            "credentials Mapping import",
        )

    marker = "\n\n\ndef load_credentials(path: Path | None = None) -> dict[str, dict[str, str]]:\n"
    helper = '''

SERVER_AUTO_CLOUD_ENGINE_ENV_VARS = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENROUTER_API_KEY",
        TOOL_CREDENTIALS["image_generate"][0],
    }
)


def active_server_cloud_credentials(
    environ: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Return names of non-empty credentials that enable server cloud routing.

    Values are used only for truthiness and are never returned.
    """
    source = os.environ if environ is None else environ
    return tuple(
        sorted(
            name
            for name in SERVER_AUTO_CLOUD_ENGINE_ENV_VARS
            if source.get(name)
        )
    )
'''
    if "def active_server_cloud_credentials(" not in text:
        if marker not in text:
            raise RuntimeError("credentials helper insertion marker not found")
        text = text.replace(marker, helper + marker, 1)

    compile(text, str(CREDENTIALS), "exec")
    CREDENTIALS.write_text(text, encoding="utf-8")


def patch_serve() -> None:
    text = SERVE.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from openjarvis.core.credentials import inject_credentials\n",
        "from openjarvis.core.credentials import (\n"
        "    active_server_cloud_credentials,\n"
        "    inject_credentials,\n"
        ")\n",
        "serve credential import",
    )
    text = replace_once(
        text,
        "    from openjarvis.core.cloud_activation import active_server_cloud_credentials\n\n",
        "",
        "serve late cloud helper import",
    )
    compile(text, str(SERVE), "exec")
    SERVE.write_text(text, encoding="utf-8")


def patch_scanner() -> None:
    text = SCANNER.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from openjarvis.core.cloud_activation import (\n"
        "    active_server_cloud_credentials,\n"
        ")\n"
        "from openjarvis.core.credentials import TOOL_CREDENTIALS\n",
        "from openjarvis.core.credentials import (\n"
        "    TOOL_CREDENTIALS,\n"
        "    active_server_cloud_credentials,\n"
        ")\n",
        "scanner credential import",
    )
    text = replace_once(
        text,
        "def _nim_host_override_present() -> bool:\n"
        "    \"\"\"Return whether NIM_HOST exists without inspecting its value.\"\"\"\n"
        "    return \"NIM_HOST\" in os.environ\n",
        "def _nim_custom_host_configured() -> bool:\n"
        "    \"\"\"Return whether runtime NIM host selection uses the env override.\"\"\"\n"
        "    return bool(os.environ.get(\"NIM_HOST\"))\n",
        "NIM runtime host semantics",
    )
    text = text.replace("_nim_host_override_present()", "_nim_custom_host_configured()")
    text = text.replace(
        "NIM_HOST is set; value was not inspected or printed",
        "NIM_HOST is non-empty; value was not emitted",
    )
    compile(text, str(SCANNER), "exec")
    SCANNER.write_text(text, encoding="utf-8")


def patch_core_test() -> None:
    text = CORE_TEST.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from openjarvis.core.cloud_activation import (\n"
        "    SERVER_AUTO_CLOUD_ENGINE_ENV_VARS,\n"
        "    active_server_cloud_credentials,\n"
        ")\n",
        "from openjarvis.cli._bootstrap import _KEY_TO_PROVIDER\n"
        "from openjarvis.core.credentials import (\n"
        "    SERVER_AUTO_CLOUD_ENGINE_ENV_VARS,\n"
        "    active_server_cloud_credentials,\n"
        ")\n",
        "core activation imports",
    )
    if "def test_server_cloud_activation_matches_bootstrap_detection():" not in text:
        text += '''


def test_server_cloud_activation_matches_bootstrap_detection():
    bootstrap_keys = frozenset(name for name, _provider in _KEY_TO_PROVIDER)
    assert SERVER_AUTO_CLOUD_ENGINE_ENV_VARS == bootstrap_keys
'''
    compile(text, str(CORE_TEST), "exec")
    CORE_TEST.write_text(text, encoding="utf-8")


def patch_security_test() -> None:
    text = SECURITY_TEST.read_text(encoding="utf-8")
    replacement = '''def test_empty_nim_host_uses_vendor_default(tmp_path, monkeypatch):
    _clear_boundary_env(monkeypatch)
    config = _low_noise_config()
    config.engine.default = "nim"
    monkeypatch.setenv("NIM_HOST", "")

    report = build_data_boundary_report(config, tmp_path)
    findings = _findings(report)

    assert findings["nim-vendor-cloud-default-endpoint"].status == "warn"
    assert "nim-custom-endpoint-configured" not in findings
'''
    text = replace_region(
        text,
        "def test_empty_nim_host_override_is_not_misclassified_as_vendor_default(",
        "def test_knowledge_plus_default_nim_is_fail(",
        replacement,
        "empty NIM host regression",
    )
    compile(text, str(SECURITY_TEST), "exec")
    SECURITY_TEST.write_text(text, encoding="utf-8")


def patch_docs() -> None:
    text = DOCS.read_text(encoding="utf-8")
    old = (
        "explicitly local, such as Ollama. NVIDIA NIM is endpoint-dependent: without\n"
        "`NIM_HOST` it uses NVIDIA's hosted API; when `NIM_HOST` is set, the scanner\n"
        "reports a custom endpoint with unknown locality without interpreting or printing\n"
        "the environment value.\n"
    )
    new = (
        "explicitly local, such as Ollama. NVIDIA NIM is endpoint-dependent: when\n"
        "`NIM_HOST` is absent or empty it uses NVIDIA's hosted API; when `NIM_HOST` is\n"
        "non-empty, the scanner reports a custom endpoint with unknown locality without\n"
        "printing the environment value.\n"
    )
    text = replace_once(text, old, new, "NIM documentation semantics")
    DOCS.write_text(text, encoding="utf-8")


patch_credentials()
patch_serve()
patch_scanner()
patch_core_test()
patch_security_test()
patch_docs()

# Staging-only automation must not survive into the candidate tree.
if WORKFLOW.exists():
    WORKFLOW.unlink()
SELF.unlink()
