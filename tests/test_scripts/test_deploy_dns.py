"""Tests for scripts/deploy_dns.py (pdns zone reload)."""

import importlib.util
from pathlib import Path

import pytest

# scripts/deploy_dns.py is a standalone script, not an installed module.
_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "deploy_dns.py"
_spec = importlib.util.spec_from_file_location("deploy_dns", _SCRIPT)
deploy_dns = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(deploy_dns)


@pytest.fixture
def layout(tmp_path, monkeypatch):
    """OUT and ETC trees where only one zone file differs (bind conf unchanged)."""
    out_etc = tmp_path / "out" / "etc"
    etc = tmp_path / "etc"
    monkeypatch.setattr(deploy_dns, "ETC", etc)
    calls: list[list[str]] = []
    monkeypatch.setattr(deploy_dns, "run", lambda argv, dry: calls.append(argv))

    def make(view: str) -> None:
        conf = f'zone "welland.mithis.com" {{ file "zones-{view}/welland.mithis.com.zone"; }};\n'
        for root in (out_etc, etc):
            (root / "powerdns" / f"zones-{view}").mkdir(parents=True)
            (root / "powerdns" / f"bind-{view}.conf").write_text(conf)
            zones = root / "powerdns" / f"zones-{view}"
            (zones / "wg.welland.mithis.com.zone").write_text("same\n")
        (out_etc / "powerdns" / f"zones-{view}" / "welland.mithis.com.zone").write_text(
            "new SSHFP\n"
        )
        (etc / "powerdns" / f"zones-{view}" / "welland.mithis.com.zone").write_text(
            "old SSHFP\n"
        )

    return out_etc, etc, calls, make


@pytest.mark.parametrize("view", ["internal", "external"])
def test_zone_only_change_reloads_exactly_the_changed_zones(layout, view):
    """`pdns_control bind-reload-now` with NO zone names reloads nothing, so the
    changed zones must be named for BOTH views (the internal view used to
    pass none and silently kept serving stale zones)."""
    out_etc, etc, calls, make = layout
    make(view)

    touched = deploy_dns.deploy_pdns(out_etc, view, dry=False)

    assert touched == [etc / "powerdns" / f"zones-{view}" / "welland.mithis.com.zone"]
    assert calls == [[
        "pdns_control", f"--config-name={view}",
        f"--socket-dir=/var/run/pdns-{view}", "bind-reload-now",
        "welland.mithis.com",
    ]]
    deployed = etc / "powerdns" / f"zones-{view}" / "welland.mithis.com.zone"
    assert deployed.read_text() == "new SSHFP\n"


def test_bind_conf_change_restarts_instead_of_reloading(layout):
    out_etc, etc, calls, make = layout
    make("internal")
    (out_etc / "powerdns" / "bind-internal.conf").write_text("changed conf\n")

    deploy_dns.deploy_pdns(out_etc, "internal", dry=False)

    assert calls == [["systemctl", "restart", "pdns@internal"]]


# --- deploy_leaves ---------------------------------------------------------
# Characterization tests pinning the behaviour that already exists, so the
# switch to the shared gdoc2netcfg.deploy_map mapping cannot change it.

@pytest.fixture
def leaves(tmp_path, monkeypatch):
    """OUT/ETC trees plus the captured systemctl calls, for deploy_leaves."""
    out_etc = tmp_path / "out" / "etc"
    etc = tmp_path / "etc"
    monkeypatch.setattr(deploy_dns, "ETC", etc)
    calls: list[list[str]] = []
    monkeypatch.setattr(deploy_dns, "run", lambda argv, dry: calls.append(argv))

    def generated(net: str) -> Path:
        d = out_etc / "dnsmasq.d" / net / "generated"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def installed(net: str) -> Path:
        d = etc / "dnsmasq.d" / net / "generated"
        d.mkdir(parents=True, exist_ok=True)
        return d

    return out_etc, etc, calls, generated, installed


def test_changed_leaf_conf_is_installed_and_only_that_net_restarts(leaves):
    out_etc, etc, calls, generated, installed = leaves
    (generated("iot") / "esp32.iot.conf").write_text("dhcp-host=aa,10.1.90.72\n")
    (installed("iot") / "esp32.iot.conf").write_text("dhcp-host=aa,10.1.90.84\n")
    (generated("int") / "desk.conf").write_text("same\n")
    (installed("int") / "desk.conf").write_text("same\n")

    touched = deploy_dns.deploy_leaves(out_etc, dry=False)

    assert touched == [etc / "dnsmasq.d" / "iot" / "generated"]
    assert calls == [["systemctl", "restart", "dnsmasq@iot"]]
    assert ((etc / "dnsmasq.d" / "iot" / "generated" / "esp32.iot.conf").read_text()
            == "dhcp-host=aa,10.1.90.72\n")


def test_generated_conf_that_disappeared_is_removed(leaves):
    out_etc, etc, calls, generated, installed = leaves
    generated("iot")
    (installed("iot") / "retired.conf").write_text("old\n")

    deploy_dns.deploy_leaves(out_etc, dry=False)

    assert not (etc / "dnsmasq.d" / "iot" / "generated" / "retired.conf").exists()
    assert calls == [["systemctl", "restart", "dnsmasq@iot"]]


def test_net_without_an_etc_directory_is_skipped(leaves, capsys):
    out_etc, etc, calls, generated, installed = leaves
    (generated("guest") / "host.conf").write_text("x\n")
    (etc / "dnsmasq.d").mkdir(parents=True)

    touched = deploy_dns.deploy_leaves(out_etc, dry=False)

    assert touched == []
    assert calls == []
    assert "SKIP guest" in capsys.readouterr().out


def test_dry_run_installs_nothing_but_previews_the_restart(leaves):
    """--dry-run writes no files; it still reports the restart it would run."""
    out_etc, etc, calls, generated, installed = leaves
    (generated("iot") / "esp32.iot.conf").write_text("new\n")
    installed("iot")

    deploy_dns.deploy_leaves(out_etc, dry=True)

    assert not (etc / "dnsmasq.d" / "iot" / "generated" / "esp32.iot.conf").exists()
    assert calls == [["systemctl", "restart", "dnsmasq@iot"]]
