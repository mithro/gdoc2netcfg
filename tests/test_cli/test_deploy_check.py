"""`gdoc2netcfg deploy-check` — is /etc what the generators would produce now?

Exit codes are the contract, because cron's `cron run` wrapper turns a non-zero
exit into mail: 0 in sync, 1 drift, 2 could not tell.  A check that cannot
compare must never look like a pass.

Passing --out compares an existing generated tree instead of generating one,
which is what these tests use: real trees on disk, no mocking.
"""

from __future__ import annotations

from pathlib import Path

import gdoc2netcfg.cli.main as cli


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def test_in_sync_tree_exits_zero(tmp_path, capsys):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "known_hosts", "ten64 ssh-ed25519 AAAA\n")
    write(etc / "ssh" / "ssh_known_hosts", "ten64 ssh-ed25519 AAAA\n")

    rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

    assert rc == 0
    assert "in sync" in capsys.readouterr().out


def test_drift_exits_one_and_names_component_and_path(tmp_path, capsys):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "dnsmasq.d" / "iot" / "generated" / "esp32.iot.conf",
          "dhcp-host=e8:3d:c1:8c:4f:d8,10.1.90.72\n")
    (etc / "dnsmasq.d" / "iot" / "generated").mkdir(parents=True)

    rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

    assert rc == 1
    output = capsys.readouterr().out
    assert "dns" in output
    assert "esp32.iot.conf" in output
    assert "missing" in output


def test_missing_generated_tree_exits_two(tmp_path, capsys):
    """Nothing to compare against is 'could not tell', not 'in sync'."""
    rc = cli.main(["deploy-check", "--out", str(tmp_path / "nope"),
                   "--etc", str(tmp_path / "etc")])

    assert rc == 2
    assert "nope" in capsys.readouterr().err


def test_skipped_nets_are_reported_without_failing(tmp_path, capsys):
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "etc" / "dnsmasq.d" / "guest" / "generated" / "host.conf", "x\n")
    (etc / "dnsmasq.d").mkdir(parents=True)

    rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

    assert rc == 0
    assert "guest" in capsys.readouterr().out


def test_listing_is_capped_but_the_reported_count_is_the_true_total(tmp_path, capsys):
    """nginx alone generates ~940 files; an uncapped list would bury the summary
    in the failure mail."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    for i in range(7):
        write(out / "nginx" / "sites-available" / f"host{i}" / "http.conf", "new\n")
        write(etc / "nginx" / "gdoc2netcfg" / "sites-available" / f"host{i}" / "http.conf",
              "old\n")

    rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc), "--limit", "2"])

    assert rc == 1
    output = capsys.readouterr().out
    assert "nginx" in output
    assert "7" in output
    # Count the LISTING lines, not every mention: the diff section names
    # each file it shows again, and it is bounded by the same --limit.
    assert len([line for line in output.splitlines()
                if line.strip().startswith("[changed]")]) == 2


def test_empty_generated_file_exits_two_rather_than_reporting_drift(tmp_path, capsys):
    """An empty generated file means the comparison is unsound: exit 2, and do
    not invite a deploy that would install the emptiness."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "known_hosts", "")
    write(etc / "ssh" / "ssh_known_hosts", "ten64 ssh-ed25519 AAAA\n")

    rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

    captured = capsys.readouterr()
    assert rc == 2
    assert "empty" in captured.out + captured.err
    assert "sudo make deploy" not in captured.out


def test_letsencrypt_drift_exits_one_and_names_component_and_path(tmp_path, capsys):
    """A departed host's leftover creation script is drift a deploy would remove."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "letsencrypt" / "certs-available" / "kept.welland.mithis.com", "same\n")
    write(etc / "letsencrypt" / "certs-available" / "kept.welland.mithis.com", "same\n")
    write(etc / "letsencrypt" / "certs-available" / "departed.welland.mithis.com", "old\n")

    rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

    assert rc == 1
    output = capsys.readouterr().out
    # The component summary line, not a bare substring: tmp_path itself
    # contains "letsencrypt" in these tests.
    assert "  letsencrypt: " in output
    assert "departed.welland.mithis.com" in output
    assert "extra" in output


def test_letsencrypt_not_deployed_here_is_reported_without_failing(tmp_path, capsys):
    """monarto generates the scripts but installs none of them; that is a site
    difference, not a pending deploy."""
    out = tmp_path / "out"
    etc = tmp_path / "etc"
    write(out / "letsencrypt" / "certs-available" / "ten64.monarto.mithis.com", "s\n")
    write(etc / "letsencrypt" / "live" / "ten64.monarto.mithis.com" / "fullchain.pem", "x\n")

    rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

    assert rc == 0
    assert "skipped letsencrypt" in capsys.readouterr().out


def test_generated_tree_requests_every_deploy_generator_by_name(tmp_path, monkeypatch):
    """letsencrypt is in no site's `[generators] enabled` list, so the scratch
    generate must name the generators explicitly or the whole tree reads as
    missing."""
    seen: list[list[str]] = []

    class _Completed:
        returncode = 0

    def fake_run(argv, *args, **kwargs):
        seen.append(argv)
        return _Completed()

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    cli.main(["deploy-check", "--etc", str(tmp_path / "etc")])

    assert len(seen) == 1
    argv = seen[0]
    assert "generate" in argv
    for generator in cli.deploy_map.DEPLOY_GENERATORS:
        assert generator in argv
    assert "letsencrypt" in argv


class TestDrifDiffs:
    """The drift list says WHICH files differ; the mail also needs to show
    HOW, so a pending deploy can be judged without ssh-ing in to diff by
    hand.  The cron wrapper mails only the last DEFAULT_TAIL_LINES lines,
    so the diffs are capped and the summary stays last."""

    def test_changed_file_shows_a_diff(self, tmp_path, capsys):
        out = tmp_path / "out"
        etc = tmp_path / "etc"
        write(out / "known_hosts", "ten64 ssh-ed25519 NEWKEY\n")
        write(etc / "ssh" / "ssh_known_hosts", "ten64 ssh-ed25519 OLDKEY\n")

        rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

        assert rc == 1
        output = capsys.readouterr().out
        assert "-ten64 ssh-ed25519 OLDKEY" in output
        assert "+ten64 ssh-ed25519 NEWKEY" in output

    def test_summary_comes_after_the_diffs(self, tmp_path, capsys):
        """cron mails the TAIL of the output, so the total must not be
        pushed out of view by a long diff."""
        out = tmp_path / "out"
        etc = tmp_path / "etc"
        write(out / "known_hosts", "new\n")
        write(etc / "ssh" / "ssh_known_hosts", "old\n")

        cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

        output = capsys.readouterr().out
        assert output.index("+new") < output.index("path(s) pending")

    def test_per_file_diff_is_capped(self, tmp_path, capsys):
        out = tmp_path / "out"
        etc = tmp_path / "etc"
        write(out / "known_hosts", "".join(f"new line {i}\n" for i in range(200)))
        write(etc / "ssh" / "ssh_known_hosts",
              "".join(f"old line {i}\n" for i in range(200)))

        cli.main(["deploy-check", "--out", str(out), "--etc", str(etc),
                  "--diff-lines", "10"])

        output = capsys.readouterr().out
        assert len([line for line in output.splitlines()
                    if line.startswith("+")]) <= 10
        assert "more diff line" in output

    def test_diff_lines_zero_disables_diffs(self, tmp_path, capsys):
        out = tmp_path / "out"
        etc = tmp_path / "etc"
        write(out / "known_hosts", "new\n")
        write(etc / "ssh" / "ssh_known_hosts", "old\n")

        rc = cli.main(["deploy-check", "--out", str(out), "--etc", str(etc),
                       "--diff-lines", "0"])

        output = capsys.readouterr().out
        assert rc == 1
        assert "ssh_known_hosts" in output
        assert "+new" not in output

    def test_missing_file_has_no_diff(self, tmp_path, capsys):
        """Nothing is installed yet, so there is nothing to diff against."""
        out = tmp_path / "out"
        etc = tmp_path / "etc"
        write(out / "known_hosts", "ten64 ssh-ed25519 KEY\n")
        (etc / "ssh").mkdir(parents=True)

        cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

        output = capsys.readouterr().out
        assert "missing" in output
        assert "@@" not in output

    def test_binary_file_is_reported_not_diffed(self, tmp_path, capsys):
        out = tmp_path / "out"
        etc = tmp_path / "etc"
        (out).mkdir(parents=True, exist_ok=True)
        (etc / "ssh").mkdir(parents=True, exist_ok=True)
        (out / "known_hosts").write_bytes(b"\xff\xfe\x00binary\n")
        (etc / "ssh" / "ssh_known_hosts").write_bytes(b"\xff\xfe\x00other\n")

        cli.main(["deploy-check", "--out", str(out), "--etc", str(etc)])

        output = capsys.readouterr().out
        # NB tmp_path embeds the test name, so asserting on the bare word
        # "binary" would pass without any implementation at all.
        assert "binary file, diff not shown" in output
