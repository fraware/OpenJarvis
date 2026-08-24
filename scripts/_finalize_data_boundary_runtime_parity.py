"""Finalize runtime-parity changes before rebuilding the clean branch.

Temporary branch-local helper. Removed before opening the upstream PR.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "src/openjarvis/security/data_boundary_audit.py"
SERVE = ROOT / "src/openjarvis/cli/serve.py"
CLI_TEST = ROOT / "tests/cli/test_scan_runtime_parity.py"
ENGINE_TEST = ROOT / "tests/engine/test_cloud_activation.py"
SECURITY_TEST = ROOT / "tests/security/test_data_boundary_runtime_parity.py"
DOC = ROOT / "docs/user-guide/data-boundary-scan.md"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def patch_scanner() -> None:
    text = SCANNER.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from openjarvis.engine.cloud_activation import (\n",
        "from openjarvis.core.cloud_activation import (\n",
        "scanner import-safe activation import",
    )
    text = replace_once(
        text,
        '    explicit_deep_engine = str(_get(config, "deep_research.engine", "") or "").strip()\n',
        '    explicit_deep_engine = str(\n'
        '        _get(config, "deep_research.engine", "") or ""\n'
        '    ).strip()\n',
        "format explicit deep-research engine",
    )
    text = replace_once(
        text,
        "    construct a cloud engine. Values are never read or printed.\n",
        "    construct a cloud engine. Credential values are never emitted.\n",
        "activation docstring accuracy",
    )
    text = replace_once(
        text,
        '            + "; values were not read or printed"\n',
        '            + "; values were not inspected or printed"\n',
        "server activation evidence accuracy",
    )
    text = replace_once(
        text,
        '            evidence=f"{selected}; NIM_HOST is set; value was not read or printed",\n',
        '            evidence=(\n'
        '                f"{selected}; NIM_HOST is set; value was not inspected or printed"\n'
        '            ),\n',
        "NIM endpoint evidence accuracy",
    )
    text = replace_once(
        text,
        '                "knowledge.db exists; NIM_HOST is set; value was not read "\n'
        '                "or printed"\n',
        '                "knowledge.db exists; NIM_HOST is set; value was not "\n'
        '                "inspected or printed"\n',
        "NIM knowledge evidence accuracy",
    )
    text = replace_once(
        text,
        '                "agent.context_from_memory = true; NIM_HOST is set; "\n'
        '                "value was not read or printed"\n',
        '                "agent.context_from_memory = true; NIM_HOST is set; "\n'
        '                "value was not inspected or printed"\n',
        "NIM memory evidence accuracy",
    )
    compile(text, str(SCANNER), "exec")
    SCANNER.write_text(text, encoding="utf-8")


def patch_serve() -> None:
    text = SERVE.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from openjarvis.engine.cloud_activation import active_server_cloud_credentials",
        "from openjarvis.core.cloud_activation import active_server_cloud_credentials",
        "serve import-safe activation import",
    )
    compile(text, str(SERVE), "exec")
    SERVE.write_text(text, encoding="utf-8")


def patch_tests() -> None:
    for path in (CLI_TEST, ENGINE_TEST):
        text = path.read_text(encoding="utf-8")
        text = text.replace(
            "from openjarvis.engine.cloud_activation import (",
            "from openjarvis.core.cloud_activation import (",
        )
        text = text.replace(
            "from openjarvis.security.data_boundary_audit import SERVER_AUTO_CLOUD_ENGINE_ENV_VARS",
            "from openjarvis.core.cloud_activation import SERVER_AUTO_CLOUD_ENGINE_ENV_VARS",
        )
        compile(text, str(path), "exec")
        path.write_text(text, encoding="utf-8")

    text = SECURITY_TEST.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "from pathlib import Path\n\n",
        "from pathlib import Path\nimport subprocess\nimport sys\n\n",
        "subprocess imports",
    )
    text = replace_once(
        text,
        "from openjarvis.core.config import JarvisConfig\n",
        "from openjarvis.core.cloud_activation import SERVER_AUTO_CLOUD_ENGINE_ENV_VARS\n"
        "from openjarvis.core.config import JarvisConfig\n",
        "shared activation test import",
    )
    text = replace_once(
        text,
        "    SERVER_AUTO_CLOUD_ENGINE_ENV_VARS,\n",
        "",
        "remove scanner re-export test import",
    )
    isolation_test = '''\n\ndef test_data_boundary_import_does_not_load_engine_package():
    code = (
        "import sys; "
        "import openjarvis.security.data_boundary_audit; "
        "assert 'openjarvis.engine' not in sys.modules, "
        "'data-boundary diagnostics must stay independent of engine imports'"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
'''
    marker = "\ndef test_config_store_paths_resolve_against_jarvis_config_schema():\n"
    text = replace_once(
        text,
        marker,
        isolation_test + marker,
        "import isolation regression",
    )
    compile(text, str(SECURITY_TEST), "exec")
    SECURITY_TEST.write_text(text, encoding="utf-8")


def patch_docs() -> None:
    text = DOC.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "reports a custom endpoint with unknown locality without reading or printing the\n"
        "environment value.\n",
        "reports a custom endpoint with unknown locality without interpreting or printing\n"
        "the environment value.\n",
        "docs endpoint wording accuracy",
    )
    DOC.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    patch_scanner()
    patch_serve()
    patch_tests()
    patch_docs()
