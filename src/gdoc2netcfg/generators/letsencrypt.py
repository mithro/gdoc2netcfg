"""Let's Encrypt certificate provisioning generator.

Produces per-host certbot scripts in certs-available/{fqdn} and a
renew-enabled.sh orchestrator. Only public FQDNs (is_fqdn=True) are
included as -d domains — short names can't be validated by Let's Encrypt.

Uses DNS-01 challenge validation via an external auth hook script
(certbot-hook-pdns) that edits the pdns@external bind-backend zone file,
bumps the SOA serial, reloads, NOTIFYs the Rollernet secondaries and waits
until the TXT is visible on the public NS. This avoids HTTP-01 failures when
AAAA records point directly to devices instead of the reverse proxy.

The hook takes no flags and no environment: `<hook> auth-hook` and
`<hook> cleanup-hook`, matching what the live renewal configs run. It
replaced certbot-hook-dnsmasq when dnsmasq@external was retired — the
dnsmasq hook's --conf-dir/--conf/--service pointed at a directory and a
systemd instance that no longer exist.

Deploy hooks are added based on hardware_type:
  - supermicro-bmc → certbot-hook-bmc-ipmi-supermicro
  - netgear-switch → certbot-hook-netgear-switches
"""

from __future__ import annotations

from gdoc2netcfg.derivations.hardware import (
    HARDWARE_NETGEAR_SWITCH,
    HARDWARE_SUPERMICRO_BMC,
)
from gdoc2netcfg.models.host import NetworkInventory
from gdoc2netcfg.utils.dns import is_safe_dns_name, is_safe_path

# Deploy hook scripts, looked up by hardware type
_DEPLOY_HOOKS: dict[str, str] = {
    HARDWARE_SUPERMICRO_BMC: "/usr/local/bin/certbot-hook-bmc-ipmi-supermicro",
    HARDWARE_NETGEAR_SWITCH: "/usr/local/bin/certbot-hook-netgear-switches",
}

_DEFAULT_AUTH_HOOK = "/opt/certbot/bin/certbot-hook-pdns"


def generate_letsencrypt(
    inventory: NetworkInventory,
    auth_hook: str = _DEFAULT_AUTH_HOOK,
) -> dict[str, str]:
    """Generate certbot provisioning scripts for each host.

    Returns a dict mapping relative paths to file contents:
      - certs-available/{primary_fqdn}   (one per host)
      - renew-enabled.sh                 (orchestrator)

    Raises:
        ValueError: If any path parameter contains unsafe characters.
    """
    if not is_safe_path(auth_hook):
        raise ValueError(f"Unsafe auth_hook: {auth_hook!r}")

    files: dict[str, str] = {}

    for host in inventory.hosts_sorted():
        # Collect only public FQDNs with safe characters
        fqdns = [
            dn.name for dn in host.dns_names
            if dn.is_fqdn and is_safe_dns_name(dn.name)
        ]

        if not fqdns:
            continue

        # Primary FQDN is the cert-name (first FQDN, typically hostname.domain)
        cert_name = fqdns[0]

        # Build certbot command
        auth_hook_cmd = f"'{auth_hook} auth-hook'"
        cleanup_hook_cmd = f"'{auth_hook} cleanup-hook'"
        lines = [
            "#!/bin/sh",
        ]
        cmd_parts = [
            "certbot certonly --manual",
            "  --preferred-challenges dns",
            f"  --manual-auth-hook {auth_hook_cmd}",
            f"  --manual-cleanup-hook {cleanup_hook_cmd}",
            f"  --cert-name {cert_name}",
        ]
        for fqdn in fqdns:
            cmd_parts.append(f"  -d {fqdn}")

        # Deploy hook based on hardware type
        hook_path = _DEPLOY_HOOKS.get(host.hardware_type or "")
        if hook_path:
            cmd_parts.append(f"  --deploy-hook {hook_path}")

        lines.append(" \\\n".join(cmd_parts))
        lines.append("")

        files[f"certs-available/{cert_name}"] = "\n".join(lines)

    # Orchestrator script
    files["renew-enabled.sh"] = (
        "#!/bin/sh\n"
        "for cert in certs-enabled/*; do\n"
        '    sh "$cert"\n'
        "done\n"
    )

    return files
