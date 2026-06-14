"""Tests for register_logins merge semantics (transport mocked)."""
from unittest.mock import patch

from gdoc2netcfg.supplements import mqtt_broker
from gdoc2netcfg.supplements.mqtt_broker import register_logins

EXISTING = [
    {"username": "gdoc2netcfg", "password": "x"},
    {"username": "DVES_USER", "password": "y"},
    {"username": "s2m-old_host", "password": "z"},
]


def _patches(captured):
    def fake_get(ssh_host):
        return {"options": {"logins": [dict(x) for x in EXISTING]}}

    def fake_post(ssh_host, logins):
        captured["posted"] = logins

    return [
        patch.object(mqtt_broker, "_supervisor_get_logins", fake_get),
        patch.object(mqtt_broker, "_supervisor_post_logins", fake_post),
        patch.object(
            mqtt_broker, "_restart_addon",
            lambda ssh_host: captured.__setitem__("restarted", True),
        ),
        patch.object(mqtt_broker, "_prehash", lambda pw: f"PREHASHED::{pw}"),
        patch.object(mqtt_broker, "_verify_login", lambda *a, **k: None),
    ]


def _run(logins, *, dry_run=False, prune=False):
    captured = {}
    ps = _patches(captured)
    for p in ps:
        p.start()
    try:
        register_logins("ha.example", "s2m-", logins, dry_run=dry_run, prune=prune)
    finally:
        for p in ps:
            p.stop()
    return captured


def _names(logins):
    return sorted(x["username"] for x in logins)


class TestRegisterLogins:
    def test_upsert_preserves_core_and_other_prefix(self):
        cap = _run({"s2m-new_host": "pw1"})
        assert _names(cap["posted"]) == ["DVES_USER", "gdoc2netcfg", "s2m-new_host", "s2m-old_host"]
        new = next(x for x in cap["posted"] if x["username"] == "s2m-new_host")
        assert new["password"] == "PREHASHED::pw1" and new["password_pre_hashed"] is True
        assert next(x for x in cap["posted"] if x["username"] == "gdoc2netcfg")["password"] == "x"
        assert cap["restarted"] is True

    def test_idempotent_no_dupes(self):
        cap = _run({"s2m-old_host": "pw"})
        assert len([x for x in cap["posted"] if x["username"] == "s2m-old_host"]) == 1

    def test_prune_drops_stale_own_prefix(self):
        cap = _run({"s2m-new_host": "pw1"}, prune=True)
        assert _names(cap["posted"]) == ["DVES_USER", "gdoc2netcfg", "s2m-new_host"]

    def test_no_prune_keeps_stale_own_prefix(self):
        cap = _run({"s2m-new_host": "pw1"}, prune=False)
        assert "s2m-old_host" in _names(cap["posted"])

    def test_dry_run_does_nothing(self):
        cap = _run({"s2m-new_host": "pw1"}, dry_run=True)
        assert "posted" not in cap and "restarted" not in cap

    def test_other_prefix_preserved(self):
        cap = _run({"s2m-x": "p"})
        assert "DVES_USER" in _names(cap["posted"]) and "gdoc2netcfg" in _names(cap["posted"])


def test_prehash_format_is_mosquitto_go_auth_pbkdf2():
    import base64 as b64
    import hashlib as hl

    h = mqtt_broker._prehash("some-plaintext")
    parts = h.split("$")
    assert len(parts) == 5
    assert parts[0] == "PBKDF2" and parts[1] == "sha512" and parts[2] == "100000"
    salt, digest = b64.b64decode(parts[3]), b64.b64decode(parts[4])
    assert len(salt) == 16 and len(digest) == 64
    # the digest is a correct PBKDF2-SHA512 of the plaintext with the embedded salt/iters
    expect = hl.pbkdf2_hmac("sha512", b"some-plaintext", salt, int(parts[2]), dklen=64)
    assert b64.b64encode(expect).decode() == parts[4]
