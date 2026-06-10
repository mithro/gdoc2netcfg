"""Tests for the SSL certificate supplement."""

from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import serialization

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, SSLCertInfo
from gdoc2netcfg.supplements.reachability import HostReachability
from gdoc2netcfg.supplements.ssl_certs import (
    enrich_hosts_with_ssl_certs,
    load_ssl_cert_cache,
    save_ssl_cert_cache,
    scan_ssl_certs,
)


def _make_host(hostname="desktop", ip="10.1.10.100"):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ip_addresses=(IPv4Address(ip),),
                dhcp_name=hostname,
            ),
        ],
    )


class TestSSLCertInfoModel:
    def test_ssl_cert_info_creation(self):
        info = SSLCertInfo(
            issuer="Let's Encrypt",
            self_signed=False,
            valid=True,
            expiry="2026-04-15",
            sans=("example.com", "www.example.com"),
        )
        assert info.issuer == "Let's Encrypt"
        assert info.self_signed is False
        assert info.valid is True
        assert info.expiry == "2026-04-15"
        assert len(info.sans) == 2

    def test_ssl_cert_info_frozen(self):
        info = SSLCertInfo(
            issuer="Test", self_signed=True, valid=False, expiry=""
        )
        try:
            info.issuer = "Modified"
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass

    def test_host_ssl_cert_info_default_none(self):
        host = _make_host()
        assert host.ssl_cert_info is None


class TestCacheIO:
    def test_load_missing_cache(self, tmp_path):
        data = load_ssl_cert_cache(tmp_path / "nonexistent.json")
        assert data == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "ssl_certs.json"
        cert_data = {
            "desktop": {
                "issuer": "Let's Encrypt",
                "self_signed": False,
                "valid": True,
                "expiry": "2026-04-15",
                "sans": ["desktop.example.com"],
            }
        }
        save_ssl_cert_cache(cache_path, cert_data)
        loaded = load_ssl_cert_cache(cache_path)
        assert loaded == cert_data

    def test_save_creates_parent_dirs(self, tmp_path):
        cache_path = tmp_path / "sub" / "dir" / "ssl_certs.json"
        save_ssl_cert_cache(cache_path, {})
        assert cache_path.exists()


class TestEnrichHosts:
    def test_enrich_with_matching_cert(self):
        host = _make_host()
        cert_data = {
            "desktop": {
                "issuer": "Let's Encrypt",
                "self_signed": False,
                "valid": True,
                "expiry": "2026-04-15",
                "sans": ["desktop.example.com"],
            }
        }
        enrich_hosts_with_ssl_certs([host], cert_data)
        assert host.ssl_cert_info is not None
        assert host.ssl_cert_info.issuer == "Let's Encrypt"
        assert host.ssl_cert_info.valid is True
        assert host.ssl_cert_info.sans == ("desktop.example.com",)

    def test_enrich_with_no_matching_cert(self):
        host = _make_host()
        enrich_hosts_with_ssl_certs([host], {})
        assert host.ssl_cert_info is None

    def test_enrich_with_self_signed_cert(self):
        host = _make_host()
        cert_data = {
            "desktop": {
                "issuer": "desktop",
                "self_signed": True,
                "valid": False,
                "expiry": "2027-01-01",
                "sans": [],
            }
        }
        enrich_hosts_with_ssl_certs([host], cert_data)
        assert host.ssl_cert_info.self_signed is True
        assert host.ssl_cert_info.valid is False


class TestScanSSLCerts:
    @patch("gdoc2netcfg.supplements.ssl_certs.check_port_open")
    @patch("gdoc2netcfg.supplements.ssl_certs._fetch_cert")
    def test_scan_finds_cert(self, mock_fetch, mock_port, tmp_path):
        mock_port.return_value = True
        mock_fetch.return_value = {
            "issuer": "Let's Encrypt",
            "self_signed": False,
            "valid": True,
            "expiry": "2026-04-15",
            "sans": ["desktop.example.com"],
        }
        reachability = {
            "desktop": HostReachability(
                hostname="desktop", active_ips=("10.1.10.100",),
            ),
        }

        host = _make_host()
        result = scan_ssl_certs(
            [host], {}, reachability=reachability,
        )

        assert "desktop" in result
        assert result["desktop"]["valid"] is True
        mock_fetch.assert_called_once_with("10.1.10.100")

    def test_scan_skips_unreachable(self, tmp_path):
        reachability = {
            "desktop": HostReachability(hostname="desktop", active_ips=()),
        }

        host = _make_host()
        result = scan_ssl_certs(
            [host], {}, reachability=reachability,
        )

        assert result == {}

    @patch("gdoc2netcfg.supplements.ssl_certs.check_port_open")
    def test_scan_skips_no_https(self, mock_port, tmp_path):
        mock_port.return_value = False
        reachability = {
            "desktop": HostReachability(
                hostname="desktop", active_ips=("10.1.10.100",),
            ),
        }

        host = _make_host()
        result = scan_ssl_certs(
            [host], {}, reachability=reachability,
        )

        assert result == {}

    @patch("gdoc2netcfg.supplements.ssl_certs.check_port_open")
    @patch("gdoc2netcfg.supplements.ssl_certs._fetch_cert")
    def test_scan_merges_baseline(self, mock_fetch, mock_port):
        """Fresh results merge over the baseline; unscanned hosts persist."""
        mock_port.return_value = True
        mock_fetch.return_value = {
            "issuer": "LE",
            "self_signed": False,
            "valid": True,
            "expiry": "2026-06-01",
            "sans": [],
        }
        reachability = {
            "desktop": HostReachability(
                hostname="desktop", active_ips=("10.1.10.100",),
            ),
        }

        host = _make_host()
        baseline = {"other": {"issuer": "Cached"}}

        result = scan_ssl_certs(
            [host], baseline, reachability=reachability,
        )

        assert "desktop" in result
        assert result["other"] == {"issuer": "Cached"}
        # The input baseline is not mutated.
        assert "desktop" not in baseline


def _make_test_cert_der(
    issuer_org: str | None = "Let's Encrypt",
    issuer_cn: str | None = "R3",
    subject_cn: str = "desktop.example.com",
    subject_org: str | None = None,
    sans: list[str] | None = None,
    self_signed: bool = False,
    days_valid: int = 90,
) -> bytes:
    """Create a test X.509 certificate in DER format.

    Supports various certificate formats:
    - CA-signed with org + CN issuer (typical Let's Encrypt, DigiCert)
    - CA-signed with CN-only issuer
    - Self-signed (issuer = subject)
    - With/without SANs
    - Various expiry periods
    """
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    # Generate a key pair
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build subject
    subject_attrs = []
    if subject_org:
        subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_org))
    subject_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_cn))
    subject = x509.Name(subject_attrs)

    # Build issuer (same as subject if self-signed)
    if self_signed:
        issuer = subject
    else:
        issuer_attrs = []
        if issuer_org:
            issuer_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org))
        if issuer_cn:
            issuer_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn))
        issuer = x509.Name(issuer_attrs)

    # Build certificate
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days_valid))
    )

    # Add SANs if provided
    if sans:
        san_list = [x509.DNSName(name) for name in sans]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


class TestFetchCert:
    @patch("gdoc2netcfg.supplements.ssl_certs.socket.create_connection")
    @patch("gdoc2netcfg.supplements.ssl_certs.ssl.create_default_context")
    def test_fetch_valid_cert(self, mock_ctx_factory, mock_conn):
        from gdoc2netcfg.supplements.ssl_certs import _fetch_cert

        # Create a real test certificate
        cert_der = _make_test_cert_der(
            issuer_org="Let's Encrypt",
            subject_cn="desktop.example.com",
            sans=["desktop.example.com", "www.example.com"],
            self_signed=False,
            days_valid=90,
        )

        # Set up mock SSL context
        mock_ctx = MagicMock()
        mock_ctx_factory.return_value = mock_ctx

        mock_sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        mock_ssock = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        # Return binary DER certificate data
        mock_ssock.getpeercert.return_value = cert_der

        result = _fetch_cert("10.1.10.100")

        assert result is not None
        assert result["issuer"] == "Let's Encrypt"
        assert result["self_signed"] is False
        assert result["valid"] is True
        assert "desktop.example.com" in result["sans"]
        assert "www.example.com" in result["sans"]

    @patch("gdoc2netcfg.supplements.ssl_certs.socket.create_connection")
    @patch("gdoc2netcfg.supplements.ssl_certs.ssl.create_default_context")
    def test_fetch_self_signed_cert(self, mock_ctx_factory, mock_conn):
        from gdoc2netcfg.supplements.ssl_certs import _fetch_cert

        # Create a self-signed certificate
        cert_der = _make_test_cert_der(
            subject_cn="myserver.local",
            sans=["myserver.local"],
            self_signed=True,
        )

        # Set up mock - first attempt fails with SSLCertVerificationError
        mock_ctx = MagicMock()
        mock_ctx_noverify = MagicMock()
        mock_ctx_factory.side_effect = [mock_ctx, mock_ctx_noverify]

        mock_sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        # First wrap_socket raises verification error
        import ssl
        mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(
            side_effect=ssl.SSLCertVerificationError(1, "certificate verify failed")
        )

        # Second wrap_socket (noverify) succeeds
        mock_ssock = MagicMock()
        mock_ctx_noverify.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ctx_noverify.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_ssock.getpeercert.return_value = cert_der

        result = _fetch_cert("10.1.10.100")

        assert result is not None
        assert result["self_signed"] is True
        assert result["valid"] is False
        assert "myserver.local" in result["sans"]

    @patch("gdoc2netcfg.supplements.ssl_certs.socket.create_connection")
    @patch("gdoc2netcfg.supplements.ssl_certs.ssl.create_default_context")
    def test_fetch_connection_refused(self, mock_ctx_factory, mock_conn):
        from gdoc2netcfg.supplements.ssl_certs import _fetch_cert

        mock_ctx_factory.return_value = MagicMock()
        mock_conn.side_effect = OSError("Connection refused")

        result = _fetch_cert("10.1.10.100")
        assert result is None


class TestCertificateFormats:
    """Tests for various real-world certificate formats."""

    def _fetch_with_mock_cert(self, cert_der: bytes) -> dict | None:
        """Helper to fetch a certificate using mocked connection."""
        from unittest.mock import MagicMock, patch

        from gdoc2netcfg.supplements.ssl_certs import _fetch_cert

        ctx_path = "gdoc2netcfg.supplements.ssl_certs.ssl.create_default_context"
        conn_path = "gdoc2netcfg.supplements.ssl_certs.socket.create_connection"
        with patch(ctx_path) as mock_ctx_factory:
            with patch(conn_path) as mock_conn:
                mock_ctx = MagicMock()
                mock_ctx_factory.return_value = mock_ctx

                mock_sock = MagicMock()
                mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
                mock_conn.return_value.__exit__ = MagicMock(return_value=False)

                mock_ssock = MagicMock()
                mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
                mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
                mock_ssock.getpeercert.return_value = cert_der

                return _fetch_cert("10.1.10.100")

    def test_letsencrypt_style_cert(self):
        """Let's Encrypt: Org + CN issuer, multiple SANs."""
        cert_der = _make_test_cert_der(
            issuer_org="Let's Encrypt",
            issuer_cn="R3",
            subject_cn="example.com",
            sans=["example.com", "www.example.com", "api.example.com"],
            self_signed=False,
            days_valid=90,
        )
        result = self._fetch_with_mock_cert(cert_der)

        assert result is not None
        assert result["issuer"] == "Let's Encrypt"
        assert result["self_signed"] is False
        assert len(result["sans"]) == 3
        assert "example.com" in result["sans"]
        assert "www.example.com" in result["sans"]
        assert "api.example.com" in result["sans"]

    def test_digicert_style_cert(self):
        """DigiCert: Different org name, wildcard SAN."""
        cert_der = _make_test_cert_der(
            issuer_org="DigiCert Inc",
            issuer_cn="DigiCert TLS RSA SHA256 2020 CA1",
            subject_cn="*.example.com",
            subject_org="Example Corp",
            sans=["*.example.com", "example.com"],
            self_signed=False,
            days_valid=365,
        )
        result = self._fetch_with_mock_cert(cert_der)

        assert result is not None
        assert result["issuer"] == "DigiCert Inc"
        assert result["self_signed"] is False
        assert "*.example.com" in result["sans"]

    def test_cn_only_issuer(self):
        """Certificate with CN-only issuer (no organization)."""
        cert_der = _make_test_cert_der(
            issuer_org=None,
            issuer_cn="myfritz.net CA",
            subject_cn="device.myfritz.net",
            sans=["device.myfritz.net", "fritz.box"],
            self_signed=False,
            days_valid=365,
        )
        result = self._fetch_with_mock_cert(cert_der)

        assert result is not None
        # Should fall back to CN when no org
        assert result["issuer"] == "myfritz.net CA"
        assert result["self_signed"] is False

    def test_no_sans_fallback_to_cn(self):
        """Certificate with no SANs - should use subject CN."""
        cert_der = _make_test_cert_der(
            issuer_org="Internal CA",
            issuer_cn="Root CA",
            subject_cn="legacy-server.local",
            sans=None,  # No SANs
            self_signed=False,
            days_valid=365,
        )
        result = self._fetch_with_mock_cert(cert_der)

        assert result is not None
        assert result["issuer"] == "Internal CA"
        # Should fall back to subject CN
        assert "legacy-server.local" in result["sans"]

    def test_many_sans_fritz_style(self):
        """Fritz box style: many SANs, far-future expiry."""
        cert_der = _make_test_cert_der(
            issuer_org=None,
            issuer_cn="abc123.myfritz.net",
            subject_cn="abc123.myfritz.net",
            sans=[
                "abc123.myfritz.net",
                "fritz.box",
                "www.fritz.box",
                "myfritz.box",
                "www.myfritz.box",
                "fritz-box-7390",
                "fritz.nas",
                "www.fritz.nas",
            ],
            self_signed=True,  # Fritz boxes are self-signed
            days_valid=365 * 20,  # ~20 years
        )
        result = self._fetch_with_mock_cert(cert_der)

        assert result is not None
        assert result["self_signed"] is True
        assert len(result["sans"]) == 8
        assert "fritz.box" in result["sans"]
        assert "fritz.nas" in result["sans"]

    def test_supermicro_bmc_style(self):
        """Supermicro BMC: Org issuer, IPMI SAN."""
        cert_der = _make_test_cert_der(
            issuer_org="Super Micro Computer",
            issuer_cn="IPMI",
            subject_cn="IPMI",
            subject_org="Super Micro Computer",
            sans=["IPMI"],
            self_signed=True,
            days_valid=365 * 5,
        )
        result = self._fetch_with_mock_cert(cert_der)

        assert result is not None
        assert result["issuer"] == "Super Micro Computer"
        assert result["self_signed"] is True
        assert "IPMI" in result["sans"]

    def test_embedded_device_cert(self):
        """Embedded device: Local hostname, very long validity."""
        cert_der = _make_test_cert_der(
            issuer_org=None,
            issuer_cn="printer.local",
            subject_cn="printer.local",
            sans=["printer.local"],
            self_signed=True,
            days_valid=365 * 100,  # 100 years (2110 expiry)
        )
        result = self._fetch_with_mock_cert(cert_der)

        assert result is not None
        assert result["issuer"] == "printer.local"
        assert result["self_signed"] is True
        # Check expiry is far in the future
        assert result["expiry"] > "2100-01-01"

    def test_near_expiry_cert(self):
        """Certificate expiring soon should parse correctly."""
        from datetime import date, timedelta

        cert_der = _make_test_cert_der(
            issuer_org="Let's Encrypt",
            issuer_cn="R3",
            subject_cn="expiring.example.com",
            sans=["expiring.example.com"],
            self_signed=False,
            days_valid=7,  # Expires in 7 days
        )
        result = self._fetch_with_mock_cert(cert_der)

        assert result is not None
        assert result["issuer"] == "Let's Encrypt"
        # Expiry date should be within the next week (relative to today)
        today = date.today()
        assert result["expiry"] >= (today + timedelta(days=6)).isoformat()
        assert result["expiry"] <= (today + timedelta(days=8)).isoformat()


class TestScanSSLCertsMultiIP:
    @patch("gdoc2netcfg.supplements.ssl_certs._fetch_cert")
    @patch("gdoc2netcfg.supplements.ssl_certs.check_port_open")
    def test_checks_all_ips_for_https(self, mock_port, mock_fetch, tmp_path):
        """Port 443 should be checked on all reachable IPs."""
        mock_port.return_value = True
        mock_fetch.return_value = {
            "issuer": "Test CA",
            "self_signed": False,
            "valid": True,
            "expiry": "2027-01-01",
            "sans": ["server.example.com"],
        }
        reachability = {
            "server": HostReachability(
                hostname="server",
                active_ips=("10.1.10.1", "2001:db8::1"),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        scan_ssl_certs(
            [host], {}, reachability=reachability,
        )

        # check_port_open should be called for both IPs
        assert mock_port.call_count == 2
        port_ips = sorted(call.args[0] for call in mock_port.call_args_list)
        assert port_ips == ["10.1.10.1", "2001:db8::1"]

    @patch("gdoc2netcfg.supplements.ssl_certs._fetch_cert")
    @patch("gdoc2netcfg.supplements.ssl_certs.check_port_open")
    def test_first_successful_cert_wins(self, mock_port, mock_fetch, tmp_path):
        """Should use cert from first IP where fetch succeeds."""
        mock_port.return_value = True
        # First IP fails, second succeeds
        mock_fetch.side_effect = [
            None,
            {
                "issuer": "Test CA",
                "self_signed": False,
                "valid": True,
                "expiry": "2027-01-01",
                "sans": ["server.example.com"],
            },
        ]
        reachability = {
            "server": HostReachability(
                hostname="server",
                active_ips=("10.1.10.1", "2001:db8::1"),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        result = scan_ssl_certs(
            [host], {}, reachability=reachability,
        )

        assert "server" in result
        assert result["server"]["issuer"] == "Test CA"
        # Both IPs should have been tried
        assert mock_fetch.call_count == 2
