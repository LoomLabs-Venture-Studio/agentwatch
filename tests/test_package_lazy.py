"""The package's lazy (PEP 562) exports keep the old `import agentwatch` API."""

import subprocess
import sys

import pytest


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          timeout=60)


def test_submodules_are_attributes_after_plain_import():
    names = ["parser", "detectors", "health", "themes", "cc_stats", "discovery"]
    proc = _run("import agentwatch, types\n"
                f"for n in {names!r}:\n"
                "    assert isinstance(getattr(agentwatch, n), types.ModuleType), n\n"
                "assert agentwatch.parser.models.ActionBuffer is agentwatch.ActionBuffer\n")
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize("name", ["nope", "_private", "__wrapped__"])
def test_unknown_names_raise_attribute_error(name):
    proc = _run(f"import agentwatch\nassert not hasattr(agentwatch, {name!r})\n"
                "import sys\nassert 'agentwatch.cli' not in sys.modules\n")
    assert proc.returncode == 0, proc.stderr
