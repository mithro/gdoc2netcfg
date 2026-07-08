"""Tests for the DNS output diff harness."""

import importlib.util
import io
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "diff_dns_output.py"
_spec = importlib.util.spec_from_file_location("diff_dns_output", _SCRIPT)
diff_dns = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(diff_dns)


def _write(tmp_path, rel, content):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def _run(tmp_path, allow_toml=None):
    allowlist = diff_dns.Allowlist([])
    if allow_toml is not None:
        allowlist = diff_dns.Allowlist.load(
            _write(tmp_path, "allow.toml", allow_toml)
        )
    out = io.StringIO()
    rc = diff_dns.run(
        [tmp_path / "old"], [tmp_path / "new"], allowlist, out=out
    )
    return rc, out.getvalue()


OLD_NATIVE = """\
host-record=host.welland.mithis.com,10.1.10.5,[2404:e80:a137:110::5]
host-record=eth0.host.welland.mithis.com,10.1.10.5
ptr-record=5.10.1.10.in-addr.arpa,eth0.host.welland.mithis.com
"""


def test_identical_data_passes(tmp_path):
    _write(tmp_path, "old/host.conf", OLD_NATIVE)
    _write(tmp_path, "new/host.conf", OLD_NATIVE)
    rc, out = _run(tmp_path)
    assert rc == 0, out
    assert "0 unexpected" in out


def test_cname_projection_is_equivalent(tmp_path):
    """native → CNAME-to-native swap with the same resolved addresses
    is NOT a difference."""
    _write(tmp_path, "old/host.conf", OLD_NATIVE)
    _write(tmp_path, "new/site.zone", """\
host.welland.mithis.com. 300 IN A 10.1.10.5
host.welland.mithis.com. 300 IN AAAA 2404:e80:a137:110::5
eth0.host.welland.mithis.com. 300 IN CNAME eth0.host.int.welland.mithis.com.
""")
    _write(tmp_path, "new/int/host.conf", """\
host-record=eth0.host.int.welland.mithis.com,10.1.10.5
ptr-record=5.10.1.10.in-addr.arpa,eth0.host.welland.mithis.com
""")
    rc, out = _run(tmp_path)
    # eth0.host.int... is an ADDED name; the site name + eth0 site name
    # must NOT be flagged
    assert "CHANGED eth0.host.welland.mithis.com" not in out
    assert "REMOVED" not in out


def test_unexpected_removal_fails(tmp_path):
    _write(tmp_path, "old/host.conf", OLD_NATIVE)
    _write(tmp_path, "new/host.conf", """\
host-record=host.welland.mithis.com,10.1.10.5,[2404:e80:a137:110::5]
""")
    rc, out = _run(tmp_path)
    assert rc == 1
    assert "REMOVED eth0.host.welland.mithis.com" in out


def test_changed_addresses_fail(tmp_path):
    _write(tmp_path, "old/host.conf", "host-record=x.welland.mithis.com,10.1.10.5\n")
    _write(tmp_path, "new/host.conf", "host-record=x.welland.mithis.com,10.1.10.6\n")
    rc, out = _run(tmp_path)
    assert rc == 1
    assert "CHANGED x.welland.mithis.com" in out


def test_allowlisted_removal_passes(tmp_path):
    _write(tmp_path, "old/host.conf", OLD_NATIVE)
    _write(tmp_path, "new/host.conf", """\
host-record=host.welland.mithis.com,10.1.10.5,[2404:e80:a137:110::5]
""")
    rc, out = _run(tmp_path, allow_toml="""\
[[allow]]
kind = "removed"
pattern = '^(5\\.10\\.1\\.10\\.in-addr\\.arpa|eth0\\.host\\.welland\\.mithis\\.com)$'
reason = "test removal"
""")
    assert rc == 0, out
    assert "ALLOWED REMOVED eth0.host.welland.mithis.com" in out


def test_sshfp_and_caa_compared(tmp_path):
    _write(tmp_path, "old/host.conf", """\
host-record=h.welland.mithis.com,10.1.10.5
dns-rr=h.welland.mithis.com,257,0005issue
dns-rr=h.welland.mithis.com,44,4:2:aabb
""")
    _write(tmp_path, "new/site.zone", """\
h.welland.mithis.com. 300 IN A 10.1.10.5
h.welland.mithis.com. 300 IN CAA 0 issue "letsencrypt.org"
h.welland.mithis.com. 300 IN SSHFP 4 2 aabb
""")
    rc, out = _run(tmp_path)
    assert rc == 0, out
