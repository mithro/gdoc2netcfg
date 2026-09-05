"""Tests for IPv4 site remapping: X-placeholder resolution and site filtering."""

import pytest

from gdoc2netcfg.derivations.ip_remap import (
    filter_and_resolve_records,
    is_record_for_site,
    resolve_site_ip,
)
from gdoc2netcfg.models.network import VLAN, Site
from gdoc2netcfg.sources.parser import DeviceRecord


def _site(name: str = "monarto", site_octet: int = 2) -> Site:
    """Build a minimal Site for testing."""
    return Site(
        name=name,
        domain=f"{name}.mithis.com",
        site_octet=site_octet,
        vlans={
            10: VLAN(id=10, name="int", subdomain="int",
                     third_octets=(8, 9, 10, 11, 12, 13, 14, 15)),
            90: VLAN(id=90, name="iot", subdomain="iot", third_octets=(90,)),
        },
    )


def _record(
    ip: str,
    site: str = "",
    mac: str = "00:11:22:33:44:55",
    machine: str = "dev",
) -> DeviceRecord:
    """Build a minimal DeviceRecord for testing."""
    return DeviceRecord(
        sheet_name="network",
        row_number=1,
        machine=machine,
        mac_address=mac,
        ip=ip,
        site=site,
    )


class TestResolveSiteIp:
    """Resolve 'X' placeholder in second octet."""

    def test_x_replaced_with_site_octet(self):
        assert resolve_site_ip("10.X.10.100", 2) == "10.2.10.100"

    def test_lowercase_x_replaced(self):
        assert resolve_site_ip("10.x.10.100", 2) == "10.2.10.100"

    def test_no_x_unchanged(self):
        assert resolve_site_ip("10.1.10.100", 2) == "10.1.10.100"

    def test_welland_octet(self):
        assert resolve_site_ip("10.X.90.5", 1) == "10.1.90.5"

    def test_monarto_octet(self):
        assert resolve_site_ip("10.X.90.5", 2) == "10.2.90.5"

    def test_non_10_prefix_with_x(self):
        """X only meaningful in second octet of 10.X.Y.Z pattern."""
        assert resolve_site_ip("192.X.1.1", 2) == "192.2.1.1"

    def test_x_in_third_octet_unchanged(self):
        """X in third octet is not replaced (only second octet)."""
        assert resolve_site_ip("10.1.X.100", 2) == "10.1.X.100"

    def test_already_correct_octet(self):
        assert resolve_site_ip("10.2.10.100", 2) == "10.2.10.100"

    def test_preserves_third_and_fourth_octets(self):
        for third in [1, 5, 10, 90, 99]:
            for fourth in [1, 100, 254]:
                result = resolve_site_ip(f"10.X.{third}.{fourth}", 2)
                assert result == f"10.2.{third}.{fourth}"


class TestIsRecordForSite:
    """Site column filtering."""

    def test_empty_site_matches_all(self):
        """Records with no site column apply to every site."""
        site = _site("monarto")
        assert is_record_for_site(_record("10.X.10.1", site=""), site) is True

    def test_matching_site(self):
        site = _site("monarto")
        assert is_record_for_site(_record("10.2.10.1", site="monarto"), site) is True

    def test_non_matching_site(self):
        site = _site("monarto")
        assert is_record_for_site(_record("10.1.10.1", site="welland"), site) is False

    def test_case_insensitive_match(self):
        site = _site("monarto")
        assert is_record_for_site(_record("10.2.10.1", site="Monarto"), site) is True

    def test_welland_site_on_welland(self):
        site = _site("welland", site_octet=1)
        assert is_record_for_site(_record("10.1.10.1", site="welland"), site) is True

    def test_monarto_site_on_welland(self):
        site = _site("welland", site_octet=1)
        assert is_record_for_site(_record("10.2.10.1", site="monarto"), site) is False


class TestFilterAndResolveRecords:
    """Integration: filter by site and resolve X placeholders."""

    def test_multi_site_record_resolved(self):
        """Record with X and no site → resolved for monarto."""
        site = _site("monarto", site_octet=2)
        records = [_record("10.X.10.100")]
        result = filter_and_resolve_records(records, site)
        assert len(result) == 1
        assert result[0].ip == "10.2.10.100"

    def test_site_specific_record_kept(self):
        """Record with site=monarto → kept as-is."""
        site = _site("monarto", site_octet=2)
        records = [_record("10.2.10.11", site="monarto")]
        result = filter_and_resolve_records(records, site)
        assert len(result) == 1
        assert result[0].ip == "10.2.10.11"

    def test_other_site_record_dropped(self):
        """Record with site=welland → dropped on monarto."""
        site = _site("monarto", site_octet=2)
        records = [_record("10.1.10.11", site="welland")]
        result = filter_and_resolve_records(records, site)
        assert len(result) == 0

    def test_mixed_records(self):
        """Realistic scenario: shared + site-specific records."""
        site = _site("monarto", site_octet=2)
        records = [
            _record("10.X.10.100", site="", machine="shared-desktop"),
            _record("10.2.10.11", site="monarto", machine="ten64"),
            _record("10.1.10.11", site="welland", machine="ten64"),
            _record("10.X.90.5", site="", machine="thermostat"),
        ]
        result = filter_and_resolve_records(records, site)
        assert len(result) == 3
        assert result[0].ip == "10.2.10.100"
        assert result[0].machine == "shared-desktop"
        assert result[1].ip == "10.2.10.11"
        assert result[1].machine == "ten64"
        assert result[2].ip == "10.2.90.5"
        assert result[2].machine == "thermostat"

    def test_same_records_for_welland(self):
        """Same mixed records generate welland output."""
        site = _site("welland", site_octet=1)
        records = [
            _record("10.X.10.100", site="", machine="shared-desktop"),
            _record("10.2.10.11", site="monarto", machine="ten64"),
            _record("10.1.10.11", site="welland", machine="ten64"),
            _record("10.X.90.5", site="", machine="thermostat"),
        ]
        result = filter_and_resolve_records(records, site)
        assert len(result) == 3
        assert result[0].ip == "10.1.10.100"
        assert result[0].machine == "shared-desktop"
        assert result[1].ip == "10.1.10.11"
        assert result[1].machine == "ten64"
        assert result[2].ip == "10.1.90.5"
        assert result[2].machine == "thermostat"

    def test_empty_records(self):
        site = _site("monarto")
        assert filter_and_resolve_records([], site) == []

    def test_original_record_not_mutated(self):
        """Records with X get new objects; originals unchanged."""
        site = _site("monarto", site_octet=2)
        original = _record("10.X.10.100")
        result = filter_and_resolve_records([original], site)
        assert original.ip == "10.X.10.100"  # unchanged
        assert result[0].ip == "10.2.10.100"

    def test_no_x_record_not_copied(self):
        """Records without X are reused (not needlessly copied)."""
        site = _site("monarto", site_octet=2)
        original = _record("10.2.10.11", site="monarto")
        result = filter_and_resolve_records([original], site)
        assert result[0] is original

    def test_dns_only_survives_x_resolution(self):
        """A none-marked (dns_only) record with an X-placeholder IP must
        keep dns_only=True after remap builds its replacement record —
        every field must propagate, not just the ones this function
        happened to know about when it was written."""
        site = _site("monarto", site_octet=2)
        original = DeviceRecord(
            sheet_name="network", row_number=5, machine="ten64",
            mac_address="", ip="10.X.98.1", dns_only=True,
        )
        result = filter_and_resolve_records([original], site)
        assert len(result) == 1
        assert result[0].ip == "10.2.98.1"
        assert result[0].dns_only is True


class TestSiteValidation:
    """Validate that site column values are recognized site names."""

    def _site_with_all(self, name: str = "welland", site_octet: int = 1) -> Site:
        return Site(
            name=name,
            domain=f"{name}.mithis.com",
            site_octet=site_octet,
            all_sites=("welland", "monarto", "ps1"),
        )

    def test_invalid_site_raises(self):
        """A site value not in all_sites raises ValueError."""
        site = self._site_with_all()
        records = [_record("10.X.90.1", site="Back Shed", machine="au-plug-28")]
        with pytest.raises(ValueError, match="invalid site value 'Back Shed'"):
            filter_and_resolve_records(records, site)

    def test_valid_other_site_filtered_not_rejected(self):
        """A valid site name for another site is filtered out, not rejected."""
        site = self._site_with_all("welland")
        records = [_record("10.2.10.1", site="monarto", machine="ten64")]
        result = filter_and_resolve_records(records, site)
        assert len(result) == 0

    def test_valid_current_site_kept(self):
        """A valid site name matching the current site is kept."""
        site = self._site_with_all("welland")
        records = [_record("10.X.10.1", site="welland", machine="desktop")]
        result = filter_and_resolve_records(records, site)
        assert len(result) == 1
        assert result[0].ip == "10.1.10.1"

    def test_empty_site_passes_validation(self):
        """Empty site value is always valid (applies to all sites)."""
        site = self._site_with_all()
        records = [_record("10.X.90.1", site="", machine="thermostat")]
        result = filter_and_resolve_records(records, site)
        assert len(result) == 1

    def test_case_insensitive_validation(self):
        """Site validation is case-insensitive."""
        site = self._site_with_all()
        records = [_record("10.2.10.1", site="Monarto", machine="ten64")]
        result = filter_and_resolve_records(records, site)
        assert len(result) == 0  # Valid but filtered (different site)

    def test_no_all_sites_skips_validation(self):
        """When all_sites is empty, no validation is performed."""
        site = _site("welland", site_octet=1)  # no all_sites
        records = [_record("10.1.90.1", site="Back Shed", machine="au-plug-28")]
        # Should not raise — validation skipped
        result = filter_and_resolve_records(records, site)
        assert len(result) == 0  # Filtered out but not rejected

    def test_section_header_without_machine_skipped(self):
        """Rows without a machine name (section headers) skip validation."""
        site = self._site_with_all()
        records = [_record("", site="Build Farm", machine="")]
        # Should not raise — no machine means it's a section header
        result = filter_and_resolve_records(records, site)
        assert len(result) == 0

    def test_error_message_includes_context(self):
        """Error message includes sheet, row, machine, and valid sites."""
        site = self._site_with_all()
        records = [DeviceRecord(
            sheet_name="iot", row_number=42,
            machine="au-plug-28", ip="10.X.90.78", site="Back Shed",
        )]
        with pytest.raises(ValueError, match=r"iot row 42.*au-plug-28.*welland, monarto, ps1"):
            filter_and_resolve_records(records, site)
