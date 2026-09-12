"""Tests for gdoc2netcfg.deploy_map — generated-vs-installed drift detection.

The mapping here is the single source of truth for "what generated file lands
where under /etc", shared with scripts/deploy_dns.py so the two cannot drift
apart.  Every test builds a real OUT tree and a real ETC tree under tmp_path;
nothing is mocked.
"""

from pathlib import Path

from gdoc2netcfg import deploy_map


def write(path: Path, text: str) -> Path:
    """Create *path*'s parents and write *text* to it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_known_hosts_in_sync_reports_no_drift(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "known_hosts", "ten64 ssh-ed25519 AAAA\n")
    write(etc / "ssh" / "ssh_known_hosts", "ten64 ssh-ed25519 AAAA\n")

    assert deploy_map.find_drift(out, etc=etc) == []


def test_known_hosts_differing_reports_changed_with_the_etc_path(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "known_hosts", "tweed ssh-ed25519 NEWKEY\n")
    write(etc / "ssh" / "ssh_known_hosts", "tweed ssh-ed25519 OLDKEY\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("known_hosts", "changed", etc / "ssh" / "ssh_known_hosts"),
    ]


def test_known_hosts_never_installed_reports_missing(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "known_hosts", "ten64 ssh-ed25519 AAAA\n")
    (etc / "ssh").mkdir(parents=True)

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind) for d in drift] == [("known_hosts", "missing")]
