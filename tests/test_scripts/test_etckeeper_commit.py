import importlib.util
import subprocess
from pathlib import Path

import pytest

# scripts/etckeeper_commit.py is a standalone script, not an installed module.
_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "etckeeper_commit.py"
_spec = importlib.util.spec_from_file_location("etckeeper_commit", _SCRIPT)
etckeeper_commit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(etckeeper_commit)


def _git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )


def _count(repo):
    out = _git(repo, "rev-list", "--count", "HEAD")
    return int(out.stdout.strip())


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "etc"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@e.st")
    _git(r, "config", "user.name", "Test")
    (r / "sub").mkdir()
    (r / "sub" / "a.conf").write_text("one\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "init")
    return r


def test_commits_a_change(repo):
    (repo / "sub" / "a.conf").write_text("two\n")
    before = _count(repo)
    rc = etckeeper_commit.main(["--repo", str(repo), "--message", "msg", str(repo / "sub")])
    assert rc == 0
    assert _count(repo) == before + 1
    subj = _git(repo, "log", "-1", "--format=%s").stdout.strip()
    assert subj == "msg"


def test_noop_exits_zero_without_committing(repo):
    before = _count(repo)
    rc = etckeeper_commit.main(["--repo", str(repo), "--message", "msg", str(repo / "sub")])
    assert rc == 0
    assert _count(repo) == before


def test_path_scoped_excludes_other_paths(repo):
    (repo / "sub" / "a.conf").write_text("changed\n")
    (repo / "other").mkdir()
    (repo / "other" / "b.conf").write_text("b\n")
    rc = etckeeper_commit.main(
        ["--repo", str(repo), "--message", "only sub", str(repo / "sub")]
    )
    assert rc == 0
    committed = _git(repo, "show", "--name-only", "--format=", "HEAD").stdout.split()
    assert "sub/a.conf" in committed
    assert "other/b.conf" not in committed
    status = _git(repo, "status", "--short").stdout
    assert "other/" in status  # still untracked, not bundled


def test_rejects_path_outside_repo(repo, tmp_path):
    outside = tmp_path / "outside.conf"
    outside.write_text("x\n")
    before = _count(repo)
    rc = etckeeper_commit.main(["--repo", str(repo), "--message", "msg", str(outside)])
    assert rc != 0
    assert _count(repo) == before


def test_hard_fail_on_commit_failure(repo):
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(0o755)
    (repo / "sub" / "a.conf").write_text("changed\n")
    rc = etckeeper_commit.main(["--repo", str(repo), "--message", "msg", str(repo / "sub")])
    assert rc != 0
