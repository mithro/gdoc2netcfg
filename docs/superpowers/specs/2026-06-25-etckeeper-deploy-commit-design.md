# etckeeper auto-commit for gdoc2netcfg deploys (#37) — Design

**Date:** 2026-06-25
**Task:** #37 — Add etckeeper integration to auto-commit /etc config changes
**Scope of this spec:** the gdoc2netcfg Makefile `deploy-*` targets only (see *Non-goals*).

## Problem

`/etc` is under etckeeper git on both production hosts (`ten64.welland`,
`ten64.monarto`), but the gdoc2netcfg **deploy** does not commit. After a
`make deploy-*`, the changed `/etc` files sit uncommitted until the next daily
cron or hook commit — which **mislabels** them (on monarto the next
`letsencrypt: auto-commit changes` would record a dnsmasq/nginx deploy under a
"letsencrypt" message). The deploy should record its own `/etc` change with a
descriptive, version-stamped commit at the moment it happens.

## Decisions (settled during brainstorming)

1. **Path-scoped commits, NOT `etckeeper commit`.** `etckeeper commit` runs
   `git add -A` and would bundle unrelated in-flight `/etc` edits (e.g. the
   operator's libvirt/apparmor work-in-progress observed on welland on
   2026-06-25) under the deploy message. Each deploy target commits **only its
   own `/etc` path(s)**.
2. **gdoc2netcfg Makefile deploy targets only.** sensors2mqtt / collector hosts
   (big-storage, sw-bb-25g) are explicitly out of scope.
3. **Version-stamped message:** `gdoc2netcfg deploy <component>: <git-describe>`
   (e.g. `gdoc2netcfg deploy nginx: v0.0-123-gabcdef`), so each `/etc` commit
   records exactly which gdoc2netcfg version produced that state.
4. **Hard-fail on commit failure.** If the commit itself fails (e.g. an
   etckeeper hook error), the helper exits non-zero so `make deploy-*` aborts
   visibly — consistent with the project's fail-loud rule. The **empty case**
   (the path has no changes) is NOT a failure: the helper exits 0 and skips.

## Architecture

A small, **tested** Python helper performs the path-scoped commit; the Makefile
deploy targets invoke it after their deploy actions. Python (not inline
Makefile shell) because it is unit-testable, DRY across the four targets, and
avoids fragile shell quoting.

```
make deploy-nginx
  ├─ generate (existing)
  ├─ rm/cp into /etc/nginx/gdoc2netcfg, nginx -t, reload   (existing)
  └─ scripts/etckeeper_commit.py --message "gdoc2netcfg deploy nginx: <ver>" \
         /etc/nginx/gdoc2netcfg                              (NEW)
        └─ git -C /etc add -- nginx/gdoc2netcfg
           if staged changes:  git -C /etc commit -m <msg>   (etckeeper pre-commit hook runs)
           else:               print "no changes", exit 0
```

## Component 1 — `scripts/etckeeper_commit.py`

**Interface (CLI):**

```
etckeeper_commit.py --message MSG [--repo REPO] PATH [PATH ...]
```

- `--message MSG` (required): commit message.
- `--repo REPO` (default `/etc`): the etckeeper git repository root. Parameterized
  so tests point it at a temporary repo.
- `PATH ...` (one or more): absolute or repo-relative paths to stage + commit.
  Paths are normalized to repo-relative for `git add -- <rel>`.

**Behavior:**

1. Normalize each `PATH` to a path relative to `REPO` (so an absolute
   `/etc/nginx/gdoc2netcfg` becomes `nginx/gdoc2netcfg`). Reject a path that is
   not under `REPO`, and reject a path that *is* `REPO` itself (relative `"."`,
   which would stage everything) — both fail loud (exit non-zero).
2. `git -C REPO add -- <rel-paths>`. On non-zero exit → print the git error to
   stderr, exit non-zero (hard fail).
3. Check whether those paths have staged changes:
   `git -C REPO diff --cached --quiet -- <rel-paths>` (exit 0 = no changes).
   - No changes → print `etckeeper_commit: no changes under <paths>, skipping`
     to stderr, **exit 0**.
4. `git -C REPO commit -m MSG -- <rel-paths>` — a **path-scoped (partial)
   commit**, so anything *unrelated* that happens to already be staged in the
   index is NOT bundled into the deploy commit. On non-zero exit → print git
   output to stderr, **exit non-zero** (hard fail).
5. Reconcile etckeeper metadata: if `REPO/.etckeeper` exists, run
   `git -C REPO add -- .etckeeper`. The partial commit committed the pre-commit
   hook's regenerated `.etckeeper` to HEAD but restored the pre-commit index,
   which would otherwise leave `.etckeeper` showing as uncommitted; re-staging
   it (working tree == HEAD after the hook) leaves the repo clean. Then print
   the new commit's short hash + subject and **exit 0**.

**Notes:**
- The git invocations use `subprocess.run` with explicit arg lists (no shell).
- **Path-scoped commit — no clean-index assumption.** Because step 4 commits
  with `-- <rel-paths>`, a dirty index (e.g. the operator's unrelated *staged*
  `/etc` edits) cannot be swept into the deploy commit; the path-scoping is a
  hard guarantee, verified by `test_does_not_bundle_pre_staged_unrelated`.
- **etckeeper `.etckeeper` metadata.** The pre-commit hook regenerates and
  `git add`s `.etckeeper` on every commit; the partial commit *does* capture it
  in the deploy commit (verified), and step 5's reconcile leaves the repo clean
  afterward — verified by `test_etckeeper_metadata_committed_and_clean`.
- Assumes it runs as root (the deploy targets are "run with sudo"), so it can
  read/write `REPO/.git`. No privilege handling in the script itself.

## Component 2 — Makefile changes

Add near the deploy section:

```make
# gdoc2netcfg version that produced the deployed /etc state (for etckeeper commits)
GDOC2NETCFG_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
ETCKEEPER_COMMIT := $(VENV_BIN)/python scripts/etckeeper_commit.py --message
```

Append one helper call to each deploy target, after its existing recipe lines:

| target | appended line |
|---|---|
| `deploy-dnsmasq-internal` | `$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy dnsmasq-internal: $(GDOC2NETCFG_VERSION)" $(DNSMASQ_CONF_DIR)/internal/generated` |
| `deploy-dnsmasq-external` | `$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy dnsmasq-external: $(GDOC2NETCFG_VERSION)" $(DNSMASQ_CONF_DIR)/external/generated` |
| `deploy-nginx` | `$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy nginx: $(GDOC2NETCFG_VERSION)" $(NGINX_GEN_DIR)` |
| `deploy-known-hosts` | `$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy known-hosts: $(GDOC2NETCFG_VERSION)" $(SSH_KNOWN_HOSTS)` |

`make deploy` (which depends on `deploy-dnsmasq deploy-nginx deploy-known-hosts`)
therefore produces up to four granular, per-component commits; each target run
on its own produces its single commit. No change to the existing
generate/cp/restart behaviour.

## Component 3 — Tests (`tests/test_scripts/test_etckeeper_commit.py`)

Pytest using a temporary git repo (`git init`, configured user, an initial
commit) as the `--repo`:

1. **Commits a change:** create/modify a file under a tracked subdir, run the
   helper for that subdir → asserts a new commit exists whose message matches
   and whose tree contains the change.
2. **No-op exits 0 without committing:** run the helper again with no changes →
   exit 0, HEAD unchanged (commit count unchanged).
3. **Path-scoping:** modify two subdirs A and B, run the helper for **A only**
   → the commit contains A's change but NOT B's; B remains uncommitted.
4. **Rejects a path outside the repo:** a `PATH` not under `--repo` → non-zero
   exit, no commit.
5. **Hard-fail on commit failure:** install a `pre-commit` hook in the temp
   repo that exits non-zero; modify a tracked path; run the helper → asserts
   the helper exits non-zero (the failed commit aborts rather than being
   swallowed).

These run as the test user against a temp repo (no `/etc`, no root, no
etckeeper package needed).

## Non-goals

- Not `etckeeper commit` (whole-`/etc`) — see decision 1.
- Not the collector hosts (big-storage, sw-bb-25g) or `/etc/sensors2mqtt/env`
  — different deploy mechanism, tracked separately.
- Does not change the existing deploy actions, the `generate`/`fetch` flow, or
  the pre-existing `make`-on-monarto `uv sync` `.stamp` quirk (orthogonal).
- Does not install or reconfigure etckeeper (already present on both ten64s).

## Rollout

Code change → normal flow + deploy-via-merge (merge to `main`, `git pull` on
both `/opt`). No service restart needed for the pull; the new behaviour takes
effect on the next `make deploy-*`.
