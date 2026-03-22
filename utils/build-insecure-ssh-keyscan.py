#!/usr/bin/env python3
"""Build insecure-ssh-keyscan from OpenSSH source with legacy algorithm support.

Downloads OpenSSH 9.8p1 portable source (last version with DSA support),
applies the insecure-kex patch (adds diffie-hellman-group1-sha1, ssh-dss,
ssh-rsa), and compiles just ssh-keyscan. The resulting binary is installed
to /usr/local/bin/insecure-ssh-keyscan.

We use 9.8p1 rather than the installed system version because OpenSSH 10.x
removed DSA entirely — no KEY_DSA, no ssh-dss, no --enable-dsa-keys. Old
devices like dropbear_2013.60 BMCs only offer ssh-dss host keys.

Must be run as root (for the final install step) or with sudo.

Usage:
    sudo python3 utils/build-insecure-ssh-keyscan.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# OpenSSH 9.8p1 — last version with DSA support. OpenSSH 10.x removed
# DSA entirely (no KEY_DSA type, no ssh-dss, no --enable-dsa-keys).
_OPENSSH_VERSION = "9.8p1"
_OPENSSH_MIRROR = "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable"

# Path to the patch file, relative to this script
_SCRIPT_DIR = Path(__file__).resolve().parent
_PATCH_FILE = _SCRIPT_DIR / "openssh-insecure-kex.patch"

# Where the binary gets installed
_INSTALL_PATH = Path("/usr/local/bin/insecure-ssh-keyscan")


def download_source(version: str, dest_dir: Path) -> Path:
    """Download and extract the OpenSSH portable source tarball."""
    tarball = f"openssh-{version}.tar.gz"
    url = f"{_OPENSSH_MIRROR}/{tarball}"
    tarball_path = dest_dir / tarball

    print(f"Downloading {url} ...")
    subprocess.run(
        ["wget", "-q", "-O", str(tarball_path), url],
        check=True,
    )

    print(f"Extracting {tarball} ...")
    subprocess.run(
        ["tar", "xzf", str(tarball_path), "-C", str(dest_dir)],
        check=True,
    )

    source_dir = dest_dir / f"openssh-{version}"
    if not source_dir.is_dir():
        raise RuntimeError(
            f"Expected source directory {source_dir} not found after extraction"
        )
    return source_dir


def apply_patch(source_dir: Path) -> None:
    """Apply the insecure KEX patch to the OpenSSH source."""
    if not _PATCH_FILE.exists():
        raise FileNotFoundError(
            f"Patch file not found: {_PATCH_FILE}"
        )

    print(f"Applying patch {_PATCH_FILE.name} ...")
    result = subprocess.run(
        ["patch", "-p1", "--forward", "-i", str(_PATCH_FILE)],
        cwd=source_dir,
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"patch stdout: {result.stdout}", file=sys.stderr)
        print(f"patch stderr: {result.stderr}", file=sys.stderr)
        raise RuntimeError(
            f"Failed to apply patch (exit code {result.returncode})"
        )
    print(result.stdout.rstrip())


def build_ssh_keyscan(source_dir: Path) -> Path:
    """Configure and build just ssh-keyscan."""
    print("Running ./configure ...")
    subprocess.run(
        [
            "./configure",
            "--enable-dsa-keys",
            "--without-pam",
            "--without-selinux",
            "--without-kerberos5",
        ],
        cwd=source_dir,
        check=True,
        stdout=subprocess.DEVNULL,
    )

    # Build just ssh-keyscan (not the full suite)
    cpu_count = os.cpu_count() or 2
    print(f"Building ssh-keyscan (make -j{cpu_count}) ...")
    subprocess.run(
        ["make", f"-j{cpu_count}", "ssh-keyscan"],
        cwd=source_dir,
        check=True,
    )

    binary = source_dir / "ssh-keyscan"
    if not binary.exists():
        raise RuntimeError(
            f"Build completed but {binary} not found"
        )
    return binary


def install_binary(binary: Path) -> None:
    """Install the built ssh-keyscan as insecure-ssh-keyscan."""
    print(f"Installing {binary} -> {_INSTALL_PATH} ...")
    shutil.copy2(binary, _INSTALL_PATH)
    _INSTALL_PATH.chmod(0o755)


def verify_binary() -> None:
    """Verify the installed binary works."""
    print("Verifying installed binary ...")
    result = subprocess.run(
        [str(_INSTALL_PATH), "-h"],
        capture_output=True, text=True,
    )
    # ssh-keyscan -h prints usage to stderr and exits non-zero,
    # but it should NOT show OpenSSL version mismatch
    if "OpenSSL version mismatch" in result.stderr:
        raise RuntimeError(
            f"Installed binary still has OpenSSL mismatch: {result.stderr}"
        )
    if "usage:" in result.stderr.lower() or "ssh-keyscan" in result.stderr.lower():
        print(f"Binary works: {result.stderr.splitlines()[0]}")
    else:
        print(f"Binary output (stderr): {result.stderr.rstrip()}")
        print(f"Binary output (stdout): {result.stdout.rstrip()}")


def main() -> int:
    # Check we can write to /usr/local/bin
    if not os.access(_INSTALL_PATH.parent, os.W_OK):
        print(
            f"Error: Cannot write to {_INSTALL_PATH.parent}. Run with sudo.",
            file=sys.stderr,
        )
        return 1

    print(f"Building insecure-ssh-keyscan from OpenSSH {_OPENSSH_VERSION}")

    # Use a temporary directory for the build
    with tempfile.TemporaryDirectory(prefix="openssh-build-") as tmpdir:
        tmp = Path(tmpdir)
        source_dir = download_source(_OPENSSH_VERSION, tmp)
        apply_patch(source_dir)
        binary = build_ssh_keyscan(source_dir)
        install_binary(binary)

    verify_binary()
    print(f"\nDone. insecure-ssh-keyscan installed at {_INSTALL_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
