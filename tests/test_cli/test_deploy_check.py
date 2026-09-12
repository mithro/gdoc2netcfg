"""`gdoc2netcfg deploy-check` — is /etc what the generators would produce now?

Exit codes are the contract, because cron's `cron run` wrapper turns a non-zero
exit into mail: 0 in sync, 1 drift, 2 could not tell.  A check that cannot
compare must never look like a pass.

Passing --out compares an existing generated tree instead of generating one,
which is what these tests use: real trees on disk, no mocking.
"""

from __future__ import annotations

from pathlib import Path

import gdoc2netcfg.cli.main as cli


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_in_sync_tree_exits_zero(tmp_path, capsys):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "known_hosts", "ten64 ssh-ed25519 AAAA\n")
    write(etc / "ssh" / "ssh_known_hosts", "ten64 ssh-ed25519 AAAA\n")

    rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

    assert rc == 0
    assert "in sync" in capsys.readouterr().out


def test_drift_exits_one_and_names_component_and_path(tmp_path, capsys):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "dnsmasq.d" / "iot" / "generated" / "esp32.iot.conf",
          "dhcp-host=e8:3d:c1:8c:4f:d8,10.1.90.72\n")
    (etc / "dnsmasq.d" / "iot" / "generated").mkdir(parents=True)

    rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

    assert rc == 1
    output = capsys.readouterr().out
    assert "dns" in output
    assert "esp32.iot.conf" in output
    assert "missing" in output


def test_missing_generated_tree_exits_two(tmp_path, capsys):
    """Nothing to compare against is 'could not tell', not 'in sync'."""
    rc = cli.main(["deploy-check", "--out", str(tmp_path / "nope"),
                   "--etc", str(tmp_path / "etc")])

    assert rc == 2
    assert "nope" in capsys.readouterr().err


def test_skipped_nets_are_reported_without_failing(tmp_path, capsys):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "dnsmasq.d" / "guest" / "generated" / "host.conf", "x\n")
    (etc / "dnsmasq.d").mkdir(parents=True)

    rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

    assert rc == 0
    assert "guest" in capsys.readouterr().out


def test_listing_is_capped_but_the_reported_count_is_the_true_total(tmp_path, capsys):
    """nginx alone generates ~940 files; an uncapped list would bury the summary
    in the failure mail."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    for i in range(7):
        write(out / "nginx" / "sites-available" / f"host{i}" / "http.conf", "new\n")
        write(etc / "nginx" / "gdoc2netcfg" / "sites-available" / f"host{i}" / "http.conf",
              "old\n")

    rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc), "--limit", "2"])

    assert rc == 1
    output = capsys.readouterr().out
    assert "nginx" in output
    assert "7" in output
    assert output.count("http.conf") == 2
