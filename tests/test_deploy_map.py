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


def test_syslog_compares_both_generated_files(tmp_path):
    """`make deploy-syslog` installs the rsyslog conf and the logrotate conf."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "rsyslog.d" / "remote-logs.conf", "new rsyslog\n")
    write(out / "etc" / "logrotate.d" / "remote-logs", "same\n")
    write(etc / "rsyslog.d" / "remote-logs.conf", "old rsyslog\n")
    write(etc / "logrotate.d" / "remote-logs", "same\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("syslog", "changed", etc / "rsyslog.d" / "remote-logs.conf"),
    ]


def test_nginx_compares_the_generated_subtrees(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "nginx" / "sites-available" / "ten64" / "http.conf", "new\n")
    write(etc / "nginx" / "gdoc2netcfg" / "sites-available" / "ten64" / "http.conf", "old\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("nginx", "changed",
         etc / "nginx" / "gdoc2netcfg" / "sites-available" / "ten64" / "http.conf"),
    ]


def test_nginx_status_txt_is_not_drift(tmp_path):
    """status.txt is created by the deploy itself and chowned to www-data; it is
    never generated, so comparing it would report drift forever."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "nginx" / "conf.d" / "shared.conf", "same\n")
    write(etc / "nginx" / "gdoc2netcfg" / "conf.d" / "shared.conf", "same\n")
    write(etc / "nginx" / "gdoc2netcfg" / "status.txt", "whatever\n")

    assert deploy_map.find_drift(out, etc=etc) == []


def test_nginx_installed_file_no_longer_generated_is_extra(tmp_path):
    """The nginx deploy wipes its subtrees, so a leftover host config would be
    removed by a real deploy — report it rather than calling /etc in sync."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "nginx" / "sites-available" / "ten64" / "http.conf", "same\n")
    write(etc / "nginx" / "gdoc2netcfg" / "sites-available" / "ten64" / "http.conf", "same\n")
    write(etc / "nginx" / "gdoc2netcfg" / "sites-available" / "retired" / "http.conf", "stale\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("nginx", "extra",
         etc / "nginx" / "gdoc2netcfg" / "sites-available" / "retired" / "http.conf"),
    ]
