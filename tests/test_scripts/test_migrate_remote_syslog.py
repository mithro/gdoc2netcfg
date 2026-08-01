"""Tests for scripts/migrate-remote-syslog.py on tmp_path trees."""

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts/migrate-remote-syslog.py"
_spec = importlib.util.spec_from_file_location("migrate_remote_syslog", _SCRIPT)
mrs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mrs)


def _make_tree(tmp_path):
    log = tmp_path / "var/log"
    etc = tmp_path / "etc"
    (log / "tasmota").mkdir(parents=True)
    (log / "network").mkdir(parents=True)
    (log / "tasmota/au-plug-1.log").write_text("t\n")
    (log / "tasmota/au-plug-1.log.1.gz").write_text("z\n")
    (log / "network/wisp.log").write_text("n\n")
    (etc / "rsyslog.d").mkdir(parents=True)
    (etc / "logrotate.d").mkdir(parents=True)
    (etc / "rsyslog.d/tasmota.conf").write_text("old\n")
    (etc / "rsyslog.d/z-network-switches.conf").write_text("old\n")
    (etc / "logrotate.d/tasmota").write_text("old\n")
    # a hand-deployed network-class logrotate file (spec: detect + remove)
    (etc / "logrotate.d/network-devices").write_text("/var/log/network/*.log {}\n")
    return log, etc


def test_dry_run_reports_and_touches_nothing(tmp_path, capsys):
    log, etc = _make_tree(tmp_path)
    mrs.migrate(log, etc, apply=False)
    out = capsys.readouterr().out
    assert "au-plug-1.log" in out and "wisp.log" in out
    # the preview also lists the source-dir removals apply will perform
    assert f"remove empty dir {log / 'tasmota'} (after moves)" in out
    assert f"remove empty dir {log / 'network'} (after moves)" in out
    assert (log / "tasmota/au-plug-1.log").exists()
    assert (etc / "rsyslog.d/tasmota.conf").exists()


def test_apply_moves_files_and_removes_configs(tmp_path):
    log, etc = _make_tree(tmp_path)
    mrs.migrate(log, etc, apply=True)
    assert (log / "iot/au-plug-1.log").read_text() == "t\n"
    assert (log / "iot/au-plug-1.log.1.gz").exists()
    assert (log / "net/wisp.log").read_text() == "n\n"
    assert not (log / "tasmota").exists()
    assert not (log / "network").exists()
    assert not (etc / "rsyslog.d/tasmota.conf").exists()
    assert not (etc / "rsyslog.d/z-network-switches.conf").exists()
    assert not (etc / "logrotate.d/tasmota").exists()
    assert not (etc / "logrotate.d/network-devices").exists()


def test_apply_is_idempotent(tmp_path):
    log, etc = _make_tree(tmp_path)
    mrs.migrate(log, etc, apply=True)
    mrs.migrate(log, etc, apply=True)  # second run: everything absent, no error
    assert (log / "iot/au-plug-1.log").exists()


def test_refuses_on_would_overwrite_conflict(tmp_path):
    log, etc = _make_tree(tmp_path)
    (log / "iot").mkdir()
    (log / "iot/au-plug-1.log").write_text("existing\n")
    with pytest.raises(SystemExit):
        mrs.migrate(log, etc, apply=True)
    # nothing was moved on refusal
    assert (log / "tasmota/au-plug-1.log").read_text() == "t\n"
