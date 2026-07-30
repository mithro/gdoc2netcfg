"""Every generator key enabled in gdoc2netcfg.toml.example must resolve
through cli/main.py::_get_generator to an importable (module, func).

This mechanically guards against generator-key renames drifting apart from
the example config (e.g. the wifi generator's earlier key): if a key in
`[generators] enabled` stops resolving, `_get_generator` returns None and
`cmd_generate` only warns at runtime -- this test turns that into a hard
failure at test time.
"""

import tomllib
from pathlib import Path

import pytest

from gdoc2netcfg.cli.main import _get_generator

_EXAMPLE_TOML = Path(__file__).resolve().parents[2] / "gdoc2netcfg.toml.example"


def _enabled_generator_names() -> list[str]:
    with open(_EXAMPLE_TOML, "rb") as f:
        data = tomllib.load(f)
    return data["generators"]["enabled"]


@pytest.mark.parametrize("name", _enabled_generator_names())
def test_enabled_generator_resolves(name):
    gen_func = _get_generator(name)
    assert gen_func is not None, (
        f"generator key {name!r} (from [generators] enabled in "
        f"gdoc2netcfg.toml.example) does not resolve via _get_generator"
    )
    assert callable(gen_func)
