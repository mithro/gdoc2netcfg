"""Register pre-hashed broker logins on the HA Mosquitto add-on.

Reaches the add-on over the existing HA SSH path (subprocess `ssh`) + the
Supervisor API. Plaintext is pre-hashed into the mosquitto-go-auth
`PBKDF2$sha512$…` PBKDF2-SHA512 format so it never lands in the add-on
options/backups. The merge is prefix-scoped: only logins starting with
`prefix` are this consumer's; everything else is preserved verbatim.

Transport (the s6-container-env token + Supervisor API over ssh) was
confirmed against the live broker by the Plan 1 / Task 1 spike.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time

import paho.mqtt.client as mqtt

_ADDON = "core_mosquitto"
_SSH_OPTS = ["-o", "ControlPath=none", "-o", "ConnectTimeout=10"]
_TOKEN = "$(cat /run/s6/container_environment/SUPERVISOR_TOKEN)"
_AUTH = f'-H "Authorization: Bearer {_TOKEN}"'


def _prehash(plaintext: str, *, iterations: int = 100_000, key_len: int = 64) -> str:
    """mosquitto-go-auth PBKDF2 hash: ``PBKDF2$sha512$<iters>$<b64 salt>$<b64 dk>``."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha512", plaintext.encode(), salt, iterations, dklen=key_len)
    return (
        f"PBKDF2$sha512${iterations}$"
        f"{base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"
    )


def _ssh(ssh_host: str, remote_cmd: str, *, stdin: str | None = None) -> str:
    result = subprocess.run(
        ["ssh", *_SSH_OPTS, ssh_host, remote_cmd],
        input=stdin, capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"ssh {ssh_host}: {result.stderr.strip()}")
    return result.stdout


def _supervisor(ssh_host: str, path: str, *, post: bool = False, body: str | None = None) -> dict:
    """Call the Supervisor API over SSH and FAIL LOUD on a non-ok result.

    ``curl -sS`` does not fail on an HTTP 4xx/5xx, so we parse the Supervisor's
    JSON envelope (``{"result": "ok"|"error", "message", "data"}``) and raise on
    ``result != "ok"``. Without this a rejected options POST silently no-ops and
    only surfaces later as a confusing auth failure. Returns the ``data`` object."""
    method = "-X POST " if post else ""
    data_flag = '-H "Content-Type: application/json" --data @- ' if body is not None else ""
    out = _ssh(
        ssh_host,
        f"curl -sS {method}{_AUTH} {data_flag}http://supervisor{path}",
        stdin=body,
    )
    try:
        resp = json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"supervisor {path}: non-JSON response: {out.strip()[:300]!r}") from exc
    if resp.get("result") != "ok":
        raise RuntimeError(f"supervisor {path}: {resp.get('message') or out.strip()[:300]}")
    return resp.get("data") or {}


def _get_addon_options(ssh_host: str) -> dict:
    """The add-on's full current options (logins + customize + anonymous + …)."""
    return _supervisor(ssh_host, f"/addons/{_ADDON}/info").get("options", {})


def _set_addon_options(ssh_host: str, options: dict) -> None:
    """Replace the add-on options. The endpoint REPLACES (not merges) and
    validates against the full schema, so the complete options object must be
    sent, wrapped in ``options`` (missing required keys like ``customize`` would
    be rejected)."""
    _supervisor(
        ssh_host, f"/addons/{_ADDON}/options",
        post=True, body=json.dumps({"options": options}),
    )


def _restart_addon(ssh_host: str) -> None:
    _supervisor(ssh_host, f"/addons/{_ADDON}/restart", post=True)


def _on_connect(res: dict):
    def handler(cl, u, f, rc, p):
        res["rc"] = rc

    return handler


def _verify_login(
    host: str, port: int, user: str, plaintext: str, *, timeout: float = 20.0
) -> None:
    """Connect once as a just-registered user; raise if the broker rejects it.
    Retries across the add-on restart window."""
    deadline = time.time() + timeout
    last: Exception | str | None = None
    while time.time() < deadline:
        res: dict = {"rc": None}
        c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="gdoc2netcfg-verify")
        c.username_pw_set(user, plaintext)
        c.on_connect = _on_connect(res)
        try:
            c.connect(host, port, keepalive=10)
            c.loop_start()
            t = time.time()
            while res["rc"] is None and time.time() - t < 3:
                time.sleep(0.1)
            c.loop_stop()
            c.disconnect()
        except OSError as e:
            last = e
            time.sleep(1.0)
            continue
        if res["rc"] == 0:
            return
        last = f"CONNACK rc={res['rc']}"
        time.sleep(1.0)
    raise RuntimeError(f"post-register login verify failed for {user}: {last}")


def register_logins(
    ssh_host: str,
    prefix: str,
    logins: dict[str, str],
    *,
    dry_run: bool = False,
    prune: bool = False,
    verify: tuple[str, int] | None = None,
) -> None:
    """Upsert `{username: plaintext}` (pre-hashed) into the add-on, scoped to
    `prefix`. Preserves every login not starting with `prefix`; with `prune`,
    drops `prefix`-logins absent from `logins`. `verify=(host, port)` connect-
    tests one login after the restart."""
    options = _get_addon_options(ssh_host)
    current = options.get("logins", [])

    kept = [x for x in current if not x["username"].startswith(prefix)]
    if not prune:
        kept += [
            x for x in current
            if x["username"].startswith(prefix) and x["username"] not in logins
        ]

    new = [
        {"username": u, "password": _prehash(p), "password_pre_hashed": True}
        for u, p in sorted(logins.items())
    ]
    merged = kept + new

    pruned = sorted(
        x["username"] for x in current
        if x["username"].startswith(prefix) and x["username"] not in logins
    ) if prune else []
    print(f"register_logins[{prefix}]: +{len(logins)} upsert, "
          f"-{len(pruned)} prune, {len(kept)} preserved", file=sys.stderr)

    if dry_run:
        print("  (dry-run: no POST / no restart)", file=sys.stderr)
        return

    options["logins"] = merged
    _set_addon_options(ssh_host, options)
    _restart_addon(ssh_host)

    if verify and logins:
        u = next(iter(sorted(logins)))
        _verify_login(verify[0], verify[1], u, logins[u])
