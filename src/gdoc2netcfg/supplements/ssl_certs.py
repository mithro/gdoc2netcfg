"""Supplement: SSL/TLS certificate scanning.

Scans hosts for TLS certificate information on port 443. Results are
cached in ssl_certs.json to avoid re-scanning on every pipeline run.

This is a Supplement, not a Source — it enriches existing Host records
with additional data from external systems (TLS endpoints).
"""

from __future__ import annotations

import socket
import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from gdoc2netcfg.models.host import Host, SSLCertInfo
from gdoc2netcfg.supplements.reachability import (
    HostReachability,
    check_port_open,
)


def _fetch_cert(ip: str, timeout: float = 5.0) -> dict | None:
    """Connect to port 443 and retrieve certificate details.

    Connects by IP address, so hostname verification is intentionally
    disabled. The 'valid' flag indicates certificate chain validity
    against the system trust store, not hostname match — hostname
    matching is the responsibility of the consumer (e.g. nginx config
    determines which cert maps to which server_name).

    Uses the cryptography library to parse the binary DER certificate,
    which works even for self-signed certificates where Python's
    getpeercert() returns minimal information.

    Returns a dict with issuer, self_signed, valid, expiry, and sans,
    or None if the connection fails.
    """
    # Chain verification context — hostname check disabled because we
    # connect by IP, not by hostname.
    ctx_verify = ssl.create_default_context()
    ctx_verify.check_hostname = False

    # Non-verifying context for retrieving self-signed cert details
    ctx_noverify = ssl.create_default_context()
    ctx_noverify.check_hostname = False
    ctx_noverify.verify_mode = ssl.CERT_NONE

    cert_der = None
    valid = False

    # Try verified first
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx_verify.wrap_socket(sock) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                valid = True
    except ssl.SSLCertVerificationError:
        # Cert exists but doesn't validate — try without verification
        try:
            with socket.create_connection((ip, 443), timeout=timeout) as sock:
                with ctx_noverify.wrap_socket(sock) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError):
            return None
    except (OSError, ssl.SSLError):
        return None

    if cert_der is None:
        return None

    # Parse with cryptography library for full details
    try:
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
    except Exception:
        return None

    # Extract issuer organization or common name
    issuer_org = _get_name_attribute(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _get_name_attribute(cert.issuer, NameOID.COMMON_NAME)
    issuer = issuer_org or issuer_cn or "Unknown"

    # Extract subject CN for SAN fallback
    subject_cn = _get_name_attribute(cert.subject, NameOID.COMMON_NAME)

    # Detect self-signed: issuer == subject (compare full Name objects)
    self_signed = cert.issuer == cert.subject

    # Extract expiry
    expiry = cert.not_valid_after_utc.strftime("%Y-%m-%d")

    # Extract SANs (Subject Alternative Names)
    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value)
    except x509.ExtensionNotFound:
        # No SAN extension — fall back to subject CN
        if subject_cn:
            sans.append(subject_cn)

    return {
        "issuer": issuer,
        "self_signed": self_signed,
        "valid": valid,
        "expiry": expiry,
        "sans": sans,
    }


def _get_name_attribute(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    """Extract a single attribute from an X.509 Name, or None if not present."""
    try:
        attrs = name.get_attributes_for_oid(oid)
        if attrs:
            return attrs[0].value
    except Exception:
        pass
    return None


def scan_ssl_certs(
    hosts: list[Host],
    baseline: dict[str, dict] | None,
    *,
    verbose: bool = False,
    reachability: dict[str, HostReachability] | None = None,
) -> dict[str, dict]:
    """Scan reachable hosts for SSL/TLS certificates on port 443.

    Args:
        hosts: Host objects with IPs to scan.
        baseline: Last-known cert data (from the DiscoveryDB).  Fresh
            results are merged over it; the caller persists the result.
        verbose: Print progress to stderr.
        reachability: Pre-computed reachability data from the
            reachability pass. Only reachable hosts are scanned.

    Returns:
        Mapping of hostname to certificate info dict.
    """
    import sys

    certs = dict(baseline or {})

    sorted_hosts = sorted(hosts, key=lambda h: h.hostname.split(".")[::-1])
    name_width = max((len(h.hostname) for h in sorted_hosts), default=0)

    for host in sorted_hosts:
        # Skip hosts not in reachability data or not reachable
        host_reach = reachability.get(host.hostname) if reachability else None
        if host_reach is None or not host_reach.is_up:
            continue
        active_ips = list(host_reach.active_ips)

        if verbose:
            print(
                f"  {host.hostname:>{name_width}s} up({','.join(active_ips)}) ",
                end="", flush=True, file=sys.stderr,
            )

        # Check HTTPS availability on all reachable IPs
        https_ips = [ip for ip in active_ips if check_port_open(ip, 443)]

        if not https_ips:
            if verbose:
                print("no-https", file=sys.stderr)
            continue

        if verbose:
            print(f"with-https({','.join(https_ips)}) ", end="", flush=True, file=sys.stderr)

        # Fetch cert from first IP that succeeds
        for https_ip in https_ips:
            cert_info = _fetch_cert(https_ip)
            if cert_info is not None:
                certs[host.hostname] = cert_info
                if verbose:
                    status = "valid" if cert_info["valid"] else "invalid"
                    issuer = cert_info["issuer"]
                    print(f"{status} ({issuer})", file=sys.stderr)
                break
        else:
            if verbose:
                print("fetch-failed", file=sys.stderr)

    return certs


def enrich_hosts_with_ssl_certs(
    hosts: list[Host],
    cert_data: dict[str, dict] | None,
) -> None:
    """Attach cached SSL cert info to Host objects.

    Modifies hosts in-place by setting host.ssl_cert_info.
    """
    cert_data = cert_data or {}
    for host in hosts:
        info = cert_data.get(host.hostname)
        if info is not None:
            host.ssl_cert_info = SSLCertInfo(
                issuer=info["issuer"],
                self_signed=info["self_signed"],
                valid=info["valid"],
                expiry=info["expiry"],
                sans=tuple(info.get("sans", [])),
            )
