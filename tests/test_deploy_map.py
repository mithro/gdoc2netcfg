"""Tests for gdoc2netcfg.deploy_map — generated-vs-installed drift detection.

The mapping here is the single source of truth for "what generated file lands
where under /etc", shared with scripts/deploy_dns.py so the two cannot drift
apart.  Every test builds a real OUT tree and a real ETC tree under tmp_path;
nothing is mocked.
"""

from pathlib import Path

from gdoc2netcfg import deploy_map


def write(path: Path, text: str) -> Path:
    """Create *path*'s parents and write *text* to it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_known_hosts_in_sync_reports_no_drift(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "known_hosts", "ten64 ssh-ed25519 AAAA\n")
    write(etc / "ssh" / "ssh_known_hosts", "ten64 ssh-ed25519 AAAA\n")

    assert deploy_map.find_drift(out, etc=etc) == []


def test_known_hosts_differing_reports_changed_with_the_etc_path(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "known_hosts", "tweed ssh-ed25519 NEWKEY\n")
    write(etc / "ssh" / "ssh_known_hosts", "tweed ssh-ed25519 OLDKEY\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("known_hosts", "changed", etc / "ssh" / "ssh_known_hosts"),
    ]


def test_known_hosts_never_installed_reports_missing(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "known_hosts", "ten64 ssh-ed25519 AAAA\n")
    (etc / "ssh").mkdir(parents=True)

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind) for d in drift] == [("known_hosts", "missing")]


def test_syslog_compares_both_generated_files(tmp_path):
    """`make deploy-syslog` installs the rsyslog conf and the logrotate conf."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "rsyslog.d" / "remote-logs.conf", "new rsyslog\n")
    write(out / "etc" / "logrotate.d" / "remote-logs", "same\n")
    write(etc / "rsyslog.d" / "remote-logs.conf", "old rsyslog\n")
    write(etc / "logrotate.d" / "remote-logs", "same\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("syslog", "changed", etc / "rsyslog.d" / "remote-logs.conf"),
    ]


def test_nginx_compares_the_generated_subtrees(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "nginx" / "sites-available" / "ten64" / "http.conf", "new\n")
    write(etc / "nginx" / "gdoc2netcfg" / "sites-available" / "ten64" / "http.conf", "old\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("nginx", "changed",
         etc / "nginx" / "gdoc2netcfg" / "sites-available" / "ten64" / "http.conf"),
    ]


def test_nginx_status_txt_is_not_drift(tmp_path):
    """status.txt is created by the deploy itself and chowned to www-data; it is
    never generated, so comparing it would report drift forever."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "nginx" / "conf.d" / "shared.conf", "same\n")
    write(etc / "nginx" / "gdoc2netcfg" / "conf.d" / "shared.conf", "same\n")
    write(etc / "nginx" / "gdoc2netcfg" / "status.txt", "whatever\n")

    assert deploy_map.find_drift(out, etc=etc) == []


def test_nginx_installed_file_no_longer_generated_is_extra(tmp_path):
    """The nginx deploy wipes its subtrees, so a leftover host config would be
    removed by a real deploy — report it rather than calling /etc in sync."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "nginx" / "sites-available" / "ten64" / "http.conf", "same\n")
    write(etc / "nginx" / "gdoc2netcfg" / "sites-available" / "ten64" / "http.conf", "same\n")
    write(etc / "nginx" / "gdoc2netcfg" / "sites-available" / "retired" / "http.conf", "stale\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("nginx", "extra",
         etc / "nginx" / "gdoc2netcfg" / "sites-available" / "retired" / "http.conf"),
    ]


def test_dnsmasq_leaf_conf_change_is_drift(tmp_path):
    """The 2026-09-12 case: a generated host reservation never installed."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "dnsmasq.d" / "iot" / "generated" / "esp32.iot.conf",
          "dhcp-host=e8:3d:c1:8c:4f:d8,10.1.90.72\n")
    (etc / "dnsmasq.d" / "iot" / "generated").mkdir(parents=True)

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("dns", "missing",
         etc / "dnsmasq.d" / "iot" / "generated" / "esp32.iot.conf"),
    ]


def test_net_absent_from_etc_is_skipped_not_drift(tmp_path):
    """deploy_leaves skips a net with no /etc/dnsmasq.d/<net>/ — a site that does
    not run that leaf is correctly configured, not stale."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "dnsmasq.d" / "guest" / "generated" / "host.conf", "x\n")
    (etc / "dnsmasq.d").mkdir(parents=True)

    assert deploy_map.find_drift(out, etc=etc) == []
    assert deploy_map.skipped_nets(out, etc=etc) == ["guest"]


def test_stale_leaf_conf_no_longer_generated_is_extra(tmp_path):
    """deploy_leaves removes generated confs that disappear, so they are drift."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "dnsmasq.d" / "iot" / "generated" / "kept.conf", "same\n")
    write(etc / "dnsmasq.d" / "iot" / "generated" / "kept.conf", "same\n")
    write(etc / "dnsmasq.d" / "iot" / "generated" / "retired.conf", "old\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("dns", "extra", etc / "dnsmasq.d" / "iot" / "generated" / "retired.conf"),
    ]


def test_pdns_zone_and_bind_conf_drift(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "powerdns" / "bind-internal.conf", "new conf\n")
    write(out / "etc" / "powerdns" / "zones-internal" / "welland.mithis.com.zone",
          "new SSHFP\n")
    write(etc / "powerdns" / "bind-internal.conf", "old conf\n")
    write(etc / "powerdns" / "zones-internal" / "welland.mithis.com.zone",
          "old SSHFP\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert {(d.kind, d.path) for d in drift} == {
        ("changed", etc / "powerdns" / "bind-internal.conf"),
        ("changed", etc / "powerdns" / "zones-internal" / "welland.mithis.com.zone"),
    }
    assert {d.component for d in drift} == {"dns"}


def test_orphaned_pdns_zone_file_is_not_drift(tmp_path):
    """deploy_pdns deliberately leaves non-generated zone files in place (hand
    extra_zones such as birds), so they must not be reported as drift."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "powerdns" / "zones-internal" / "welland.mithis.com.zone", "z\n")
    write(etc / "powerdns" / "zones-internal" / "welland.mithis.com.zone", "z\n")
    write(etc / "powerdns" / "zones-internal" / "birds.welland.mithis.com.zone", "hand\n")

    assert deploy_map.find_drift(out, etc=etc) == []


def test_recursor_forward_zones_drift(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "powerdns" / "forward-zones.yml", "new\n")
    write(etc / "powerdns" / "forward-zones.yml", "old\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("dns", "changed", etc / "powerdns" / "forward-zones.yml"),
    ]


def test_empty_generated_file_against_installed_content_is_not_called_stale(tmp_path):
    """A generator that produced nothing is a broken run, not a pending deploy.

    Seen for real: running with a config whose relative .cache resolved to the
    wrong directory produced a 0-byte known_hosts, which compared as ordinary
    drift against the live 237 KB file — i.e. it invited a deploy that would
    have wiped every host key.
    """
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "known_hosts", "")
    write(etc / "ssh" / "ssh_known_hosts", "ten64 ssh-ed25519 AAAA\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind) for d in drift] == [("known_hosts", "empty")]


def test_empty_generated_file_is_fine_when_etc_is_empty_too(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "known_hosts", "")
    write(etc / "ssh" / "ssh_known_hosts", "")

    assert deploy_map.find_drift(out, etc=etc) == []


def test_letsencrypt_is_in_the_deploy_set_deploy_check_generates():
    """deploy-check generates DEPLOY_GENERATORS by name, so letsencrypt has to be
    in it: the generator is in no site's `[generators] enabled` list, and a
    component absent from the deploy set is one whose drift goes unnoticed."""
    assert "letsencrypt" in deploy_map.DEPLOY_GENERATORS


def test_letsencrypt_in_sync_reports_no_drift(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "letsencrypt" / "certs-available" / "ten64.welland.mithis.com", "s\n")
    write(out / "letsencrypt" / "renew-enabled.sh", "#!/bin/sh\n")
    write(etc / "letsencrypt" / "certs-available" / "ten64.welland.mithis.com", "s\n")
    write(etc / "letsencrypt" / "renew-enabled.sh", "#!/bin/sh\n")

    assert deploy_map.find_drift(out, etc=etc) == []


def test_letsencrypt_cert_script_change_is_drift(tmp_path):
    """The 2026-09-14 case: every deployed script still named the retired
    certbot-hook-dnsmasq months after the generator moved to certbot-hook-pdns."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "letsencrypt" / "certs-available" / "tweed.welland.mithis.com",
          "certbot certonly --manual-auth-hook 'certbot-hook-pdns auth-hook'\n")
    write(etc / "letsencrypt" / "certs-available" / "tweed.welland.mithis.com",
          "certbot certonly --manual-auth-hook 'certbot-hook-dnsmasq auth-hook'\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("letsencrypt", "changed",
         etc / "letsencrypt" / "certs-available" / "tweed.welland.mithis.com"),
    ]


def test_letsencrypt_new_host_script_never_installed_is_missing(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "letsencrypt" / "certs-available" / "new-host.welland.mithis.com", "s\n")
    (etc / "letsencrypt" / "certs-available").mkdir(parents=True)

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("letsencrypt", "missing",
         etc / "letsencrypt" / "certs-available" / "new-host.welland.mithis.com"),
    ]


def test_letsencrypt_departed_host_script_is_extra(tmp_path):
    """`make deploy-letsencrypt` wipes certs-available/ before copying, so a
    script for a host that left the sheet is drift a deploy would clean up — and
    a stale creation script is how a cert gets made for a host that is gone."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "letsencrypt" / "certs-available" / "kept.welland.mithis.com", "same\n")
    write(etc / "letsencrypt" / "certs-available" / "kept.welland.mithis.com", "same\n")
    write(etc / "letsencrypt" / "certs-available" / "departed.welland.mithis.com", "old\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("letsencrypt", "extra",
         etc / "letsencrypt" / "certs-available" / "departed.welland.mithis.com"),
    ]


def test_letsencrypt_renew_enabled_script_is_compared(tmp_path):
    """The deploy copies renew-enabled.sh too — a plain cp, so it can never be
    'extra', but it must still be compared."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "letsencrypt" / "certs-available" / "kept.welland.mithis.com", "same\n")
    write(out / "letsencrypt" / "renew-enabled.sh", "new orchestrator\n")
    write(etc / "letsencrypt" / "certs-available" / "kept.welland.mithis.com", "same\n")
    write(etc / "letsencrypt" / "renew-enabled.sh", "old orchestrator\n")

    drift = deploy_map.find_drift(out, etc=etc)

    assert [(d.component, d.kind, d.path) for d in drift] == [
        ("letsencrypt", "changed", etc / "letsencrypt" / "renew-enabled.sh"),
    ]


def test_letsencrypt_live_certs_outside_the_wiped_subtree_are_not_extra(tmp_path):
    """Only certs-available/ is wiped; certbot's own /etc/letsencrypt content is
    never touched by the deploy, so it must not be reported."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "letsencrypt" / "certs-available" / "kept.welland.mithis.com", "same\n")
    write(etc / "letsencrypt" / "certs-available" / "kept.welland.mithis.com", "same\n")
    write(etc / "letsencrypt" / "renewal" / "kept.welland.mithis.com.conf", "certbot\n")
    write(etc / "letsencrypt" / "live" / "kept.welland.mithis.com" / "fullchain.pem", "x\n")

    assert deploy_map.find_drift(out, etc=etc) == []


def test_letsencrypt_not_deployed_at_this_site_is_skipped_not_drift(tmp_path):
    """monarto has the generator configured but no deployed certs-available/ (it
    manages its certs with certbot directly), so there is nothing to compare —
    the same treatment a net with no /etc/dnsmasq.d/<net>/ gets."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "letsencrypt" / "certs-available" / "ten64.monarto.mithis.com", "s\n")
    write(out / "letsencrypt" / "renew-enabled.sh", "#!/bin/sh\n")
    write(etc / "letsencrypt" / "live" / "ten64.monarto.mithis.com" / "fullchain.pem", "x\n")

    assert deploy_map.find_drift(out, etc=etc) == []
    assert deploy_map.letsencrypt_skipped(out, etc=etc) is True


def test_letsencrypt_skipped_is_false_where_the_tree_is_deployed(tmp_path):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "letsencrypt" / "certs-available" / "ten64.welland.mithis.com", "s\n")
    write(etc / "letsencrypt" / "certs-available" / "ten64.welland.mithis.com", "s\n")

    assert deploy_map.letsencrypt_skipped(out, etc=etc) is False


class TestDeployTargetCoverage:
    """`make deploy` must run a target for every component deploy-check compares.

    deploy-check tells the operator "Deploy with: sudo make deploy".  If a
    compared component has no target in that rule, following the instruction
    cannot clear the drift, and the 05:00 cron check mails root about it every
    morning forever.  The coupling used to be a comment; these tests make it
    enforceable.
    """

    def _deploy_prerequisites(self) -> set[str]:
        makefile = Path(__file__).resolve().parents[1] / "Makefile"
        for line in makefile.read_text().splitlines():
            if line.startswith("deploy:"):
                body = line.split(":", 1)[1].split("##")[0]
                return set(body.split())
        raise AssertionError("no `deploy:` target found in the Makefile")

    def test_every_compared_component_has_a_make_target(self):
        missing = set(deploy_map.DEPLOY_GENERATORS) - set(deploy_map.DEPLOY_TARGETS)
        assert not missing, (
            f"components compared by deploy-check with no make target: {missing}"
        )

    def test_deploy_runs_a_target_for_every_compared_component(self):
        prereqs = self._deploy_prerequisites()
        missing = {
            component: deploy_map.DEPLOY_TARGETS[component]
            for component in deploy_map.DEPLOY_GENERATORS
            if deploy_map.DEPLOY_TARGETS[component] not in prereqs
        }
        assert not missing, (
            "`make deploy` does not run these components' targets, so the "
            f"drift it reports cannot be cleared by it: {missing}"
        )
