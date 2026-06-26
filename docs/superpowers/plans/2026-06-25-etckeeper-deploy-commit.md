# etckeeper Deploy Auto-Commit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make each `make deploy-*` record its `/etc` change in etckeeper's git with a path-scoped, version-stamped commit.

**Architecture:** A small tested Python helper (`scripts/etckeeper_commit.py`) stages + commits only the named paths in the etckeeper repo (default `/etc`); the Makefile `deploy-*` targets call it after their existing deploy actions. Path-scoped (never `git add -A`/`etckeeper commit`) so unrelated in-flight `/etc` edits are never bundled.

**Tech Stack:** Python 3 stdlib (`argparse`, `subprocess`, `pathlib`); pytest; GNU Make. Run Python via `uv run`. Spec: `docs/superpowers/specs/2026-06-25-etckeeper-deploy-commit-design.md`.

## Global Constraints

- Commits are **path-scoped** only — `git -C <repo> add -- <paths>` then `git commit`; NEVER `git add -A` or `etckeeper commit`.
- Commit message format (verbatim): `gdoc2netcfg deploy <component>: <git-describe>` where `<component>` ∈ {`dnsmasq-internal`, `dnsmasq-external`, `nginx`, `known-hosts`}.
- Exit codes: a path with **no staged changes → exit 0** and skip (a no-op deploy must not error); an actual **git commit failure → exit non-zero** (hard fail, aborts the deploy).
- A `PATH` not under `--repo` → exit non-zero (fail loud, do not commit).
- Helper uses `subprocess.run` with explicit arg lists — **never `shell=True`**.
- Scope is the gdoc2netcfg Makefile `deploy-*` targets only — NOT collector hosts, NOT `/etc/sensors2mqtt/env`, NOT etckeeper install/config.
- Do not change existing generate/fetch/cp/restart behaviour.
- Lint clean: `uv run ruff check src/ tests/ scripts/` (scripts may not currently be linted — at minimum the new file must be ruff-clean).

---

### Task 1: `scripts/etckeeper_commit.py` helper + tests (TDD)

**Files:**
- Create: `scripts/etckeeper_commit.py`
- Create: `tests/test_scripts/test_etckeeper_commit.py`
- Note: `tests/test_scripts/__init__.py` already exists (do not recreate).

**Interfaces:**
- Produces: `main(argv: list[str] | None = None) -> int` in `scripts/etckeeper_commit.py`. CLI: `etckeeper_commit.py --message MSG [--repo /etc] PATH [PATH ...]`. Returns process exit code (0 success/no-op, non-zero on rejection or commit failure). Importable with no side effects at import time (all logic under `main()`, called only from `if __name__ == "__main__"`).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_scripts/test_etckeeper_commit.py`:

```python
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
    assert "other/b.conf" in status  # still untracked, not bundled


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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_scripts/test_etckeeper_commit.py -v`
Expected: collection/exec error or all FAIL — `scripts/etckeeper_commit.py` does not exist yet (importlib `exec_module` raises `FileNotFoundError`).

- [ ] **Step 3: Write the helper**

Create `scripts/etckeeper_commit.py`:

```python
#!/usr/bin/env python3
"""Path-scoped etckeeper commit for gdoc2netcfg deploys.

Stages and commits ONLY the given paths in the etckeeper git repo (default
/etc), so a deploy records its own change without bundling unrelated in-flight
/etc edits. No staged changes -> exit 0 (skip); commit failure -> exit non-zero.
"""
import argparse
import subprocess
import sys
from pathlib import Path


def _git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description="Path-scoped etckeeper commit.")
    parser.add_argument("--message", required=True, help="commit message")
    parser.add_argument(
        "--repo", default="/etc", help="etckeeper git repo root (default: /etc)"
    )
    parser.add_argument(
        "paths", nargs="+", help="paths under --repo to stage and commit"
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()

    rel_paths = []
    for p in args.paths:
        abs_p = Path(p).resolve()
        try:
            rel_paths.append(str(abs_p.relative_to(repo)))
        except ValueError:
            print(
                f"etckeeper_commit: {p!r} is not under repo {repo}", file=sys.stderr
            )
            return 2

    add = _git(repo, "add", "--", *rel_paths)
    if add.returncode != 0:
        print(f"etckeeper_commit: git add failed:\n{add.stderr}", file=sys.stderr)
        return add.returncode or 1

    # Exit 0 from `diff --cached --quiet` means nothing is staged for these paths.
    diff = _git(repo, "diff", "--cached", "--quiet", "--", *rel_paths)
    if diff.returncode == 0:
        print(
            f"etckeeper_commit: no changes under {rel_paths}, skipping",
            file=sys.stderr,
        )
        return 0

    commit = _git(repo, "commit", "-m", args.message)
    if commit.returncode != 0:
        print(
            f"etckeeper_commit: git commit failed:\n{commit.stdout}\n{commit.stderr}",
            file=sys.stderr,
        )
        return commit.returncode or 1

    print(commit.stdout.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_scripts/test_etckeeper_commit.py -v`
Expected: 5 passed.

- [ ] **Step 5: Lint**

Run: `uv run ruff check scripts/etckeeper_commit.py tests/test_scripts/test_etckeeper_commit.py`
Expected: `All checks passed!` (fix any findings, e.g. import order, line length).

- [ ] **Step 6: Commit**

```bash
git add scripts/etckeeper_commit.py tests/test_scripts/test_etckeeper_commit.py
git commit -m "feat: path-scoped etckeeper commit helper for deploys (#37)"
```

---

### Task 2: Wire the Makefile deploy targets + document

**Files:**
- Modify: `Makefile` (deploy section, lines ~65–99)
- Modify: `CLAUDE.md` (deploy docs — one note)

**Interfaces:**
- Consumes: `scripts/etckeeper_commit.py` `main()` CLI from Task 1, invoked as `$(VENV_BIN)/python scripts/etckeeper_commit.py --message <msg> <path>`.

- [ ] **Step 1: Add the version + commit-helper variables**

In `Makefile`, immediately after the line `DNSMASQ_CONF_DIR := /etc/dnsmasq.d` (currently line 66), insert:

```make

# gdoc2netcfg version that produced the deployed /etc state (for etckeeper commits)
GDOC2NETCFG_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
# Path-scoped etckeeper commit of a deploy. Usage: $(ETCKEEPER_COMMIT) "<msg>" <path>
ETCKEEPER_COMMIT := $(VENV_BIN)/python scripts/etckeeper_commit.py --message
```

- [ ] **Step 2: Append the commit to `deploy-dnsmasq-internal`**

In `deploy-dnsmasq-internal`, after `systemctl restart dnsmasq@internal`, add a new tab-indented recipe line:

```make
	$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy dnsmasq-internal: $(GDOC2NETCFG_VERSION)" $(DNSMASQ_CONF_DIR)/internal/generated
```

- [ ] **Step 3: Append the commit to `deploy-dnsmasq-external`**

In `deploy-dnsmasq-external`, after `systemctl restart dnsmasq@external`, add:

```make
	$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy dnsmasq-external: $(GDOC2NETCFG_VERSION)" $(DNSMASQ_CONF_DIR)/external/generated
```

- [ ] **Step 4: Append the commit to `deploy-nginx`**

In `deploy-nginx`, after `systemctl reload nginx`, add:

```make
	$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy nginx: $(GDOC2NETCFG_VERSION)" $(NGINX_GEN_DIR)
```

- [ ] **Step 5: Append the commit to `deploy-known-hosts`**

In `deploy-known-hosts`, after `cp $(OUTPUT_DIR)/known_hosts $(SSH_KNOWN_HOSTS)`, add:

```make
	$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy known-hosts: $(GDOC2NETCFG_VERSION)" $(SSH_KNOWN_HOSTS)
```

- [ ] **Step 6: Verify the Makefile wiring with a dry run**

Run: `make -n deploy-nginx | grep etckeeper_commit`
Expected: one line like
`.venv/bin/python scripts/etckeeper_commit.py --message "gdoc2netcfg deploy nginx: <version>" /etc/nginx/gdoc2netcfg`
where `<version>` is the resolved `git describe` output (e.g. `v0.0-NN-gXXXXXXX`). Confirm the message is a single quoted argument and the path is `/etc/nginx/gdoc2netcfg`.

Also run: `make -n deploy | grep -c etckeeper_commit`
Expected: `4` (one commit per component across the full deploy).

- [ ] **Step 7: Document the behaviour in CLAUDE.md**

In `CLAUDE.md`, in the dnsmasq "Fetch, generate, and deploy" area (the section showing `make`/`cp`/restart deploy steps), add a short note. Find the dnsmasq deploy code block under `#### Fetch, generate, and deploy` and immediately after that block insert:

```markdown
Each `make deploy-*` target also records its `/etc` change in etckeeper's git
via `scripts/etckeeper_commit.py` — a **path-scoped** commit (only that
target's `/etc` path, never `etckeeper commit`/`git add -A`, so unrelated
in-flight `/etc` edits are not bundled) with message
`gdoc2netcfg deploy <component>: <git-describe>`. A path with no changes is a
no-op; a failed commit aborts the deploy.
```

- [ ] **Step 8: Run the full test suite + lint (no regressions)**

Run: `uv run pytest -q`
Expected: all pass (prior count + 5 new).
Run: `uv run ruff check src/ tests/ scripts/`
Expected: `All checks passed!`

- [ ] **Step 9: Commit**

```bash
git add Makefile CLAUDE.md
git commit -m "feat: auto-commit /etc to etckeeper on make deploy-* (#37)"
```

---

## Self-Review

**1. Spec coverage:**
- Decision 1 (path-scoped) → Task 1 helper (`git add -- <paths>`, no `-A`) + Global Constraints + Task 1 `test_path_scoped_excludes_other_paths`. ✓
- Decision 2 (gdoc2netcfg only) → scope stated; Makefile targets only. ✓
- Decision 3 (version-stamped message) → Task 2 `GDOC2NETCFG_VERSION` + the four messages; Task 2 Step 6 verifies. ✓
- Decision 4 (hard-fail; empty=exit 0) → Task 1 helper exit logic + tests `test_noop_exits_zero_without_committing` and `test_hard_fail_on_commit_failure`. ✓
- Component 1 (helper interface/behavior) → Task 1. Component 2 (Makefile) → Task 2. Component 3 (tests, 5 cases) → Task 1 Step 1 (all 5 present). ✓
- Clean-index assumption / `.etckeeper` hook → covered by behavior; `test_path_scoped_excludes_other_paths` exercises the untracked-unrelated case. ✓

**2. Placeholder scan:** No TBD/TODO; all code blocks complete; exact paths and commands given. ✓

**3. Type consistency:** `main(argv)->int` defined in Task 1, consumed by Task 2 via the documented CLI (`--message`, `--repo`, positional `paths`). Message strings and component names match the Global Constraints exactly. ✓
