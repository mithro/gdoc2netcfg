"""logrotate policy for the shared dnsmasq log (``/etc/logrotate.d/dnsmasq``).

Every per-net ``dnsmasq@<net>`` instance writes to one file, set by
``log-facility`` in ``/etc/dnsmasq.d/shared/05-logging.conf``.  That conf is
hand-maintained (no generator emits it), so the path cannot be derived from
generated output: ``DNSMASQ_LOG_FILE`` is the one place in this repo that names
it, and it must match that ``log-facility`` line.

The postrotate signals the instances by glob, never by name.  The hand-kept
file it replaces named ``dnsmasq@internal``/``dnsmasq@external``, units retired
by the dns-redesign, so the 2026-09-20 rotation told no instance to reopen its
log and they all kept writing into ``dnsmasq.log.1`` (342 MB).  dnsmasq reopens
its ``log-facility`` file on SIGUSR2, and ``systemctl kill`` accepts unit-name
patterns, so one line covers whatever nets a site runs.

The output does not depend on the inventory; it is a generator so that
``make deploy`` installs it and ``deploy-check`` reports drift in it.
"""

from __future__ import annotations

from gdoc2netcfg.models.host import NetworkInventory

#: dnsmasq's ``log-facility`` (hand-maintained in
#: /etc/dnsmasq.d/shared/05-logging.conf).  Keep the two in step.
DNSMASQ_LOG_FILE = "/var/log/dnsmasq.log"


def generate_dnsmasq_logrotate(
    inventory: NetworkInventory | None,
) -> dict[str, str]:
    """Return ``{"logrotate.d/dnsmasq": text}``, deploy-relative under /etc."""
    return {
        "logrotate.d/dnsmasq": f"""\
{DNSMASQ_LOG_FILE} {{
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
}}
""",
    }
