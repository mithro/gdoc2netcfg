"""Tests for the dnsmasq logrotate generator.

Every per-net dnsmasq@<net> instance logs to one shared file (the
``log-facility`` line in the hand-maintained
/etc/dnsmasq.d/shared/05-logging.conf).  The 2026-09-20 rotation named the
retired dnsmasq@internal/@external units in its postrotate, so no instance
reopened its log and all of them kept writing into dnsmasq.log.1 (342 MB).
"""

from gdoc2netcfg.generators.dnsmasq_logrotate import (
    DNSMASQ_LOG_FILE,
    generate_dnsmasq_logrotate,
)

#: The file installed by hand at both sites on 2026-09-26, byte for byte.
#: The first generated deploy must be a no-op, so this is the contract.
EXPECTED = """\
/var/log/dnsmasq.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    # dnsmasq runs as user 'nobody' (no user= set); the new file MUST be
    # writable by it, else dnsmasq cannot reopen on USR2 (see dnsmasq(8)).
    create 0640 nobody adm
    postrotate
        /usr/bin/systemctl kill --signal=USR2 'dnsmasq@*.service'
    endscript
}
"""


def test_emits_only_the_logrotate_file():
    assert list(generate_dnsmasq_logrotate(None)) == ["logrotate.d/dnsmasq"]


def test_output_is_byte_identical_to_the_installed_file():
    assert generate_dnsmasq_logrotate(None)["logrotate.d/dnsmasq"] == EXPECTED


def test_rotates_the_log_facility_file():
    text = generate_dnsmasq_logrotate(None)["logrotate.d/dnsmasq"]
    assert DNSMASQ_LOG_FILE == "/var/log/dnsmasq.log"
    assert text.startswith(f"{DNSMASQ_LOG_FILE} {{\n")


def test_postrotate_signals_every_instance_not_named_units():
    """Naming units is what broke: a glob cannot go stale as nets come and go."""
    text = generate_dnsmasq_logrotate(None)["logrotate.d/dnsmasq"]
    assert "systemctl kill --signal=USR2 'dnsmasq@*.service'" in text
    assert "dnsmasq@internal" not in text
