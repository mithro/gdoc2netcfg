"""_build_pipeline reads supplements from the SQLite DBs only (#4 cutover).

The flat-file caches are no longer consulted: a supplement present only as
a flat .json must contribute NO enrichment, while the same data in
discovery.db must enrich. (The flat files remain only as scan working
files until the scan-side cutover removes them entirely.)
"""

import base64
import textwrap

from gdoc2netcfg.cli.main import _build_pipeline
from gdoc2netcfg.config import load_config

_KEY_B64 = base64.b64encode(b"test-ed25519-key-blob").decode()


def _write_config(tmp_path):
    """Minimal site config with a cached network.csv (no Google fetch)."""
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()
    (cache_dir / "network.csv").write_text(
        "Machine,MAC Address,IP,Interface\n"
        "server1,aa:bb:cc:dd:ee:03,10.1.10.5,\n"
    )
    config_path = tmp_path / "gdoc2netcfg.toml"
    config_path.write_text(textwrap.dedent(f"""\
        [site]
        name = "test"
        domain = "test.example.com"

        [sheets]
        network = "https://example.com/not-used"

        [cache]
        directory = "{cache_dir}"

        [ipv6]
        prefixes = ["2001:db8:1:"]

        [vlans]
        10 = {{ name = "int", subdomain = "int" }}

        [network_subdomains]
        10 = "int"

        [generators]
        enabled = []
    """))
    return config_path, cache_dir


def _ssh_keys_for(hostname):
    return [f"{hostname} ssh-ed25519 {_KEY_B64}"]


def test_flat_supplement_cache_is_not_read(tmp_path):
    """Flat ssh_host_keys.json without DBs must NOT enrich hosts."""
    config_path, cache_dir = _write_config(tmp_path)
    config = load_config(config_path)

    # Discover the derived hostname, then plant a flat cache for it.
    _, hosts, _, _ = _build_pipeline(config)
    (host,) = hosts
    from gdoc2netcfg.supplements.sshfp import save_ssh_host_keys_cache
    save_ssh_host_keys_cache(
        cache_dir / "ssh_host_keys.json",
        {host.hostname: _ssh_keys_for(host.hostname)},
    )

    config = load_config(config_path)
    _, hosts, _, _ = _build_pipeline(config)
    (host,) = hosts
    assert host.ssh_host_keys == []
    assert host.sshfp_records == []


def test_db_supplement_is_read(tmp_path):
    """The same data in discovery.db DOES enrich hosts."""
    config_path, cache_dir = _write_config(tmp_path)
    config = load_config(config_path)

    _, hosts, _, _ = _build_pipeline(config)
    (host,) = hosts
    keys = _ssh_keys_for(host.hostname)

    from gdoc2netcfg.storage import open_databases
    dbs = open_databases(cache_dir)  # creates config.db + discovery.db
    scan_id = dbs.discovery.begin_scan("ssh_host_keys")
    dbs.discovery.save_ssh_host_keys(scan_id, {host.hostname: keys})
    dbs.discovery.finish_scan(scan_id, host_count=1, changed_count=1)
    dbs.close()

    config = load_config(config_path)
    _, hosts, _, _ = _build_pipeline(config)
    (host,) = hosts
    assert host.ssh_host_keys == keys
    assert host.sshfp_records != []
