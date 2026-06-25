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
