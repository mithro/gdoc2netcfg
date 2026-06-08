"""Tests for the Sites sheet parser."""

from gdoc2netcfg.sources.sites_parser import parse_sites, site_names

# Mirrors the real Sites tab: header at row 0, then a mix of site rows,
# a '---' marker, a per-host IPv6 /56 allocation ('ten64.welland'), a
# near-empty 'special' site, and a 'Decommisioned' marker (empty Shortname).
SAMPLE = """\
Domain,Shortname,Public IPv4,Private IPv4,IPv6,Provider,City,Country,Address,GPS
welland.mithis.com,welland,87.121.95.37,10.1.X.X,2404:e80:a137::/48,Launtel,Welland,AU,Tce,
,---,,,2404:e80:a137:00::/56,,,,,
ten64.welland.mithis.com,ten64.welland,,,2404:e80:a137:01::/56,,,,,
monarto.mithis.com,monarto,,10.2.X.X,,Starlink,Monarto,AU,"4 Schenscher Rd",
,special,,,,,,,,
ps1.mithis.com,ps1,,,,,Chicago,US,,
Decommisioned,,,,,,,,,
"""


def test_parse_sites_returns_only_site_rows():
    sites = parse_sites(SAMPLE)
    assert [s.shortname for s in sites] == ["welland", "monarto", "special", "ps1"]


def test_parse_sites_populates_all_columns():
    welland = next(s for s in parse_sites(SAMPLE) if s.shortname == "welland")
    assert welland.domain == "welland.mithis.com"
    assert welland.public_ipv4 == "87.121.95.37"
    assert welland.private_ipv4 == "10.1.X.X"
    assert welland.ipv6 == "2404:e80:a137::/48"
    assert welland.provider == "Launtel"
    assert welland.city == "Welland"
    assert welland.country == "AU"


def test_parse_sites_excludes_per_host_allocations():
    # 'ten64.welland' has a dot -> per-host IPv6 /56 allocation, not a site.
    assert "ten64.welland" not in [s.shortname for s in parse_sites(SAMPLE)]


def test_parse_sites_excludes_markers_and_empty():
    names = [s.shortname for s in parse_sites(SAMPLE)]
    assert "---" not in names
    assert "" not in names
    assert "decommisioned" not in names


def test_parse_sites_lowercases_shortname():
    # Device sheet uses 'Welland'/'Monarto'; all_sites is lowercased, so the
    # parser must lowercase too for the two to match.
    sites = parse_sites("Domain,Shortname\nFOO.mithis.com,FOO\n")
    assert [s.shortname for s in sites] == ["foo"]


def test_parse_sites_keeps_special_with_empty_fields():
    special = next(s for s in parse_sites(SAMPLE) if s.shortname == "special")
    assert special.domain == ""
    assert special.public_ipv4 == ""


def test_site_names_returns_tuple():
    assert site_names(parse_sites(SAMPLE)) == ("welland", "monarto", "special", "ps1")


def test_parse_sites_empty_input():
    assert parse_sites("") == []


def test_parse_sites_missing_shortname_column():
    assert parse_sites("Domain,Foo\nx.com,bar\n") == []
