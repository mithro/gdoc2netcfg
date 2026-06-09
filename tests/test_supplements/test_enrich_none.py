"""Each supplement enricher must tolerate None (no data) without crashing.

This is the precondition for #4: once the flat-file fallback is removed,
_build_pipeline passes the DB result straight through, which is None for a
supplement that has no scan (e.g. monarto has no BMCs / Netgear switches).
"""
import types

import pytest

from gdoc2netcfg.supplements.bmc_firmware import enrich_hosts_with_bmc_firmware
from gdoc2netcfg.supplements.bridge import enrich_hosts_with_bridge_data
from gdoc2netcfg.supplements.nsdp import enrich_hosts_with_nsdp
from gdoc2netcfg.supplements.snmp import enrich_hosts_with_snmp
from gdoc2netcfg.supplements.sshfp import enrich_hosts_with_ssh_host_keys
from gdoc2netcfg.supplements.ssl_certs import enrich_hosts_with_ssl_certs
from gdoc2netcfg.supplements.tasmota import enrich_hosts_with_tasmota

ENRICHERS = [
    enrich_hosts_with_snmp,
    enrich_hosts_with_bridge_data,
    enrich_hosts_with_bmc_firmware,
    enrich_hosts_with_nsdp,
    enrich_hosts_with_tasmota,
    enrich_hosts_with_ssh_host_keys,
    enrich_hosts_with_ssl_certs,
]


@pytest.mark.parametrize("enrich", ENRICHERS, ids=lambda f: f.__name__)
def test_enricher_tolerates_none(enrich):
    # A host the loop will visit (so the coalesce path is actually exercised).
    host = types.SimpleNamespace(hostname="host-a", extra={})
    enrich([host], None)  # must not raise


@pytest.mark.parametrize("enrich", ENRICHERS, ids=lambda f: f.__name__)
def test_enricher_tolerates_empty(enrich):
    host = types.SimpleNamespace(hostname="host-a", extra={})
    enrich([host], {})  # must not raise
