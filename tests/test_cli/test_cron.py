"""Tests for cron job management (cli/cron.py)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# CronEntry data model
# ---------------------------------------------------------------------------

class TestCronEntry:
    """Tests for the CronEntry dataclass."""

    def test_cron_entry_fields(self):
        """CronEntry should store schedule, command, lock_name, and comment."""
        from gdoc2netcfg.cli.cron import CronEntry

        entry = CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs from Google Sheets",
        )
        assert entry.schedule == "*/15 * * * *"
        assert entry.command == "gdoc2netcfg fetch"
        assert entry.lock_name == "fetch"
        assert entry.comment == "Fetch CSVs from Google Sheets"

    def test_cron_entry_is_frozen(self):
        """CronEntry should be immutable (frozen dataclass)."""
        from gdoc2netcfg.cli.cron import CronEntry

        entry = CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs",
        )
        with pytest.raises(AttributeError):
            entry.schedule = "0 * * * *"


# ---------------------------------------------------------------------------
# Path detection: detect_uv_path
# ---------------------------------------------------------------------------

class TestDetectUvPath:
    """Tests for detect_uv_path()."""

    def test_finds_uv_via_which(self):
        """Should find uv via shutil.which() first."""
        from gdoc2netcfg.cli.cron import detect_uv_path

        with patch("shutil.which", return_value="/usr/bin/uv"):
            result = detect_uv_path()
        assert result == Path("/usr/bin/uv")

    def test_falls_back_to_local_bin(self, tmp_path):
        """When which() fails, should check ~/.local/bin/uv."""
        from gdoc2netcfg.cli.cron import detect_uv_path

        fake_uv = tmp_path / ".local" / "bin" / "uv"
        fake_uv.parent.mkdir(parents=True)
        fake_uv.touch()

        with (
            patch("shutil.which", return_value=None),
            patch("pathlib.Path.home", return_value=tmp_path),
        ):
            result = detect_uv_path()
        assert result == fake_uv

    def test_falls_back_to_usr_local_bin(self, tmp_path):
        """When which() and ~/.local/bin fail, should check /usr/local/bin/uv."""
        from gdoc2netcfg.cli.cron import detect_uv_path

        original_exists = Path.exists

        def fake_exists(path):
            if str(path) == "/usr/local/bin/uv":
                return True
            return original_exists(path)

        with (
            patch("shutil.which", return_value=None),
            patch("pathlib.Path.home", return_value=tmp_path),
            patch.object(Path, "exists", fake_exists),
        ):
            result = detect_uv_path()
        assert result == Path("/usr/local/bin/uv")

    def test_raises_when_not_found(self, tmp_path):
        """Should raise FileNotFoundError with install instructions when uv not found."""
        from gdoc2netcfg.cli.cron import detect_uv_path

        original_exists = Path.exists

        def fake_exists(path):
            if str(path) == "/usr/local/bin/uv":
                return False
            return original_exists(path)

        with (
            patch("shutil.which", return_value=None),
            patch("pathlib.Path.home", return_value=tmp_path),
            patch.object(Path, "exists", fake_exists),
        ):
            with pytest.raises(FileNotFoundError, match="uv"):
                detect_uv_path()


# ---------------------------------------------------------------------------
# Path detection: detect_project_root
# ---------------------------------------------------------------------------

class TestDetectProjectRoot:
    """Tests for detect_project_root()."""

    def test_finds_in_cwd(self, tmp_path):
        """Should find project root when gdoc2netcfg.toml is in cwd."""
        from gdoc2netcfg.cli.cron import detect_project_root

        (tmp_path / "gdoc2netcfg.toml").touch()

        result = detect_project_root(tmp_path)
        assert result == tmp_path

    def test_finds_in_parent(self, tmp_path):
        """Should walk up and find project root in a parent directory."""
        from gdoc2netcfg.cli.cron import detect_project_root

        (tmp_path / "gdoc2netcfg.toml").touch()
        subdir = tmp_path / "src" / "gdoc2netcfg"
        subdir.mkdir(parents=True)

        result = detect_project_root(subdir)
        assert result == tmp_path

    def test_raises_when_not_found(self, tmp_path):
        """Should raise FileNotFoundError when no gdoc2netcfg.toml found."""
        from gdoc2netcfg.cli.cron import detect_project_root

        with pytest.raises(FileNotFoundError, match="gdoc2netcfg.toml"):
            detect_project_root(tmp_path)


# ---------------------------------------------------------------------------
# Cron entry generation
# ---------------------------------------------------------------------------

class TestGenerateCronEntries:
    """Tests for generate_cron_entries()."""

    def test_returns_correct_count(self):
        """Should return 8 CronEntry objects (per the agreed schedule)."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        assert len(entries) == 8

    def test_fetch_schedule(self):
        """Fetch should run every 15 minutes."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        fetch = [e for e in entries if e.lock_name == "fetch"]
        assert len(fetch) == 1
        assert fetch[0].schedule == "*/15 * * * *"

    def test_generate_schedule(self):
        """Generate should run every 15 minutes."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        gen = [e for e in entries if e.lock_name == "generate"]
        assert len(gen) == 1
        assert gen[0].schedule == "*/15 * * * *"

    def test_reachability_schedule(self):
        """Reachability should run every 30 minutes."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        reach = [e for e in entries if e.lock_name == "reachability"]
        assert len(reach) == 1
        assert reach[0].schedule == "*/30 * * * *"

    def test_sshfp_schedule(self):
        """SSHFP should run daily at 02:00."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        sshfp = [e for e in entries if e.lock_name == "sshfp"]
        assert len(sshfp) == 1
        assert sshfp[0].schedule == "0 2 * * *"

    def test_ssl_certs_schedule(self):
        """SSL certs should run daily at 02:05."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        ssl = [e for e in entries if e.lock_name == "ssl-certs"]
        assert len(ssl) == 1
        assert ssl[0].schedule == "5 2 * * *"

    def test_snmp_schedule(self):
        """SNMP should run daily at 03:00."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        snmp = [e for e in entries if e.lock_name == "snmp"]
        assert len(snmp) == 1
        assert snmp[0].schedule == "0 3 * * *"

    def test_bridge_schedule(self):
        """Bridge should run daily at 03:05."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        bridge = [e for e in entries if e.lock_name == "bridge"]
        assert len(bridge) == 1
        assert bridge[0].schedule == "5 3 * * *"

    def test_bmc_firmware_schedule(self):
        """BMC firmware should run weekly on Sunday at 04:00."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        bmc = [e for e in entries if e.lock_name == "bmc-firmware"]
        assert len(bmc) == 1
        assert bmc[0].schedule == "0 4 * * 0"

    def test_all_lock_names_unique(self):
        """All lock names should be unique."""
        from gdoc2netcfg.cli.cron import generate_cron_entries

        entries = generate_cron_entries()
        lock_names = [e.lock_name for e in entries]
        assert len(lock_names) == len(set(lock_names))


# ---------------------------------------------------------------------------
# Cron line formatting
# ---------------------------------------------------------------------------

class TestFormatCronLine:
    """Tests for format_cron_line()."""

    def test_contains_schedule(self):
        """Formatted line should start with the cron schedule."""
        from gdoc2netcfg.cli.cron import CronEntry, format_cron_line

        entry = CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs",
        )
        line = format_cron_line(entry, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))
        assert line.startswith("*/15 * * * *")

    def test_contains_flock(self):
        """Formatted line should include flock with non-blocking flag."""
        from gdoc2netcfg.cli.cron import CronEntry, format_cron_line

        entry = CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs",
        )
        line = format_cron_line(entry, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))
        assert "flock -n" in line

    def test_lock_file_path(self):
        """Lock file should be in .cache/ under the project root."""
        from gdoc2netcfg.cli.cron import CronEntry, format_cron_line

        entry = CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs",
        )
        line = format_cron_line(entry, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))
        assert "/opt/gdoc2netcfg/.cache/cron-fetch.lock" in line

    def test_uses_uv_with_directory(self):
        """Should use 'uv --directory <project> run <command>'."""
        from gdoc2netcfg.cli.cron import CronEntry, format_cron_line

        entry = CronEntry(
            schedule="0 2 * * *",
            command="gdoc2netcfg sshfp",
            lock_name="sshfp",
            comment="Scan SSH fingerprints",
        )
        line = format_cron_line(entry, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))
        assert "/usr/bin/uv --directory /opt/gdoc2netcfg run gdoc2netcfg sshfp" in line

    def test_appends_to_log_file(self):
        """Output should be appended to .cache/cron.log."""
        from gdoc2netcfg.cli.cron import CronEntry, format_cron_line

        entry = CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs",
        )
        line = format_cron_line(entry, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))
        assert ">>/opt/gdoc2netcfg/.cache/cron.log 2>&1" in line

    def test_rejects_uv_path_with_whitespace(self):
        """Should raise ValueError if uv path contains whitespace."""
        from gdoc2netcfg.cli.cron import CronEntry, format_cron_line

        entry = CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs",
        )
        with pytest.raises(ValueError, match="whitespace"):
            format_cron_line(entry, Path("/home/user name/bin/uv"), Path("/opt/gdoc2netcfg"))

    def test_rejects_project_root_with_whitespace(self):
        """Should raise ValueError if project root contains whitespace."""
        from gdoc2netcfg.cli.cron import CronEntry, format_cron_line

        entry = CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs",
        )
        with pytest.raises(ValueError, match="whitespace"):
            format_cron_line(entry, Path("/usr/bin/uv"), Path("/opt/my project"))


# ---------------------------------------------------------------------------
# Crontab block formatting
# ---------------------------------------------------------------------------

class TestFormatCrontabBlock:
    """Tests for format_crontab_block()."""

    def test_has_begin_marker(self):
        """Block should start with BEGIN marker."""
        from gdoc2netcfg.cli.cron import format_crontab_block, generate_cron_entries

        entries = generate_cron_entries()
        block = format_crontab_block(entries, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))
        assert "# BEGIN gdoc2netcfg managed entries" in block

    def test_has_end_marker(self):
        """Block should end with END marker."""
        from gdoc2netcfg.cli.cron import format_crontab_block, generate_cron_entries

        entries = generate_cron_entries()
        block = format_crontab_block(entries, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))
        assert "# END gdoc2netcfg managed entries" in block

    def test_has_project_path_comment(self):
        """Block should include the project path as a comment."""
        from gdoc2netcfg.cli.cron import format_crontab_block, generate_cron_entries

        entries = generate_cron_entries()
        block = format_crontab_block(entries, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))
        assert "# Project: /opt/gdoc2netcfg" in block

    def test_contains_all_entries(self):
        """Block should contain all 8 cron lines."""
        from gdoc2netcfg.cli.cron import format_crontab_block, generate_cron_entries

        entries = generate_cron_entries()
        block = format_crontab_block(entries, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))
        # Count lines that start with a cron schedule (not comments)
        cron_lines = [
            line for line in block.splitlines()
            if line and not line.startswith("#")
        ]
        assert len(cron_lines) == 8

    def test_ends_with_newline(self):
        """Block should end with a trailing newline."""
        from gdoc2netcfg.cli.cron import format_crontab_block, generate_cron_entries

        entries = generate_cron_entries()
        block = format_crontab_block(entries, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))
        assert block.endswith("\n")


# ---------------------------------------------------------------------------
# Crontab reading/writing
# ---------------------------------------------------------------------------

class TestReadCurrentCrontab:
    """Tests for read_current_crontab()."""

    def test_reads_existing_crontab(self):
        """Should return the current crontab contents."""
        from gdoc2netcfg.cli.cron import read_current_crontab

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "0 * * * * some-job\n"
            mock_run.return_value.returncode = 0
            result = read_current_crontab()
        assert result == "0 * * * * some-job\n"
        mock_run.assert_called_once()

    def test_returns_empty_when_no_crontab(self):
        """Should return empty string when 'no crontab for user' error."""
        import subprocess

        from gdoc2netcfg.cli.cron import read_current_crontab

        err = subprocess.CalledProcessError(1, "crontab -l")
        err.stderr = "no crontab for user\n"

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = err
            result = read_current_crontab()
        assert result == ""

    def test_raises_on_unexpected_crontab_error(self):
        """Should re-raise CalledProcessError for unexpected errors."""
        import subprocess

        from gdoc2netcfg.cli.cron import read_current_crontab

        err = subprocess.CalledProcessError(1, "crontab -l")
        err.stderr = "permission denied\n"

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = err
            with pytest.raises(subprocess.CalledProcessError):
                read_current_crontab()


class TestWriteCrontab:
    """Tests for write_crontab()."""

    def test_pipes_content_to_crontab(self):
        """Should pipe content to 'crontab -'."""
        from gdoc2netcfg.cli.cron import write_crontab

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            write_crontab("0 * * * * some-job\n")
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0] == ["crontab", "-"]
        assert call_args[1]["input"] == "0 * * * * some-job\n"


# ---------------------------------------------------------------------------
# Block manipulation
# ---------------------------------------------------------------------------

class TestRemoveManagedBlock:
    """Tests for remove_managed_block()."""

    def test_removes_block_between_markers(self):
        """Should remove everything between BEGIN and END markers (inclusive)."""
        from gdoc2netcfg.cli.cron import remove_managed_block

        crontab = (
            "0 * * * * other-job\n"
            "# BEGIN gdoc2netcfg managed entries - DO NOT EDIT THIS BLOCK\n"
            "# Project: /opt/gdoc2netcfg\n"
            "*/15 * * * * flock ...\n"
            "# END gdoc2netcfg managed entries\n"
            "30 * * * * another-job\n"
        )
        result = remove_managed_block(crontab)
        assert "BEGIN gdoc2netcfg" not in result
        assert "END gdoc2netcfg" not in result
        assert "flock" not in result
        assert "0 * * * * other-job" in result
        assert "30 * * * * another-job" in result

    def test_preserves_content_when_no_block(self):
        """Should return crontab unchanged when no managed block exists."""
        from gdoc2netcfg.cli.cron import remove_managed_block

        crontab = "0 * * * * other-job\n30 * * * * another-job\n"
        result = remove_managed_block(crontab)
        assert result == crontab

    def test_handles_empty_crontab(self):
        """Should handle empty crontab gracefully."""
        from gdoc2netcfg.cli.cron import remove_managed_block

        result = remove_managed_block("")
        assert result == ""

    def test_raises_on_begin_without_end(self):
        """Should raise ValueError when BEGIN marker has no matching END."""
        from gdoc2netcfg.cli.cron import remove_managed_block

        crontab = (
            "0 * * * * other-job\n"
            "# BEGIN gdoc2netcfg managed entries - DO NOT EDIT THIS BLOCK\n"
            "*/15 * * * * flock ...\n"
        )
        with pytest.raises(ValueError, match="BEGIN.*without.*END"):
            remove_managed_block(crontab)

    def test_raises_on_end_without_begin(self):
        """Should raise ValueError when END marker has no preceding BEGIN."""
        from gdoc2netcfg.cli.cron import remove_managed_block

        crontab = (
            "0 * * * * other-job\n"
            "# END gdoc2netcfg managed entries\n"
            "30 * * * * another-job\n"
        )
        with pytest.raises(ValueError, match="END.*without.*BEGIN"):
            remove_managed_block(crontab)

    def test_no_trailing_blank_lines(self):
        """Should not leave multiple trailing blank lines after removal."""
        from gdoc2netcfg.cli.cron import remove_managed_block

        crontab = (
            "0 * * * * other-job\n"
            "\n"
            "# BEGIN gdoc2netcfg managed entries - DO NOT EDIT THIS BLOCK\n"
            "*/15 * * * * flock ...\n"
            "# END gdoc2netcfg managed entries\n"
        )
        result = remove_managed_block(crontab)
        # Should not have multiple trailing newlines
        assert not result.endswith("\n\n")


class TestAddManagedBlock:
    """Tests for add_managed_block()."""

    def test_appends_to_empty_crontab(self):
        """Should add block to empty crontab."""
        from gdoc2netcfg.cli.cron import add_managed_block

        block = (
            "# BEGIN gdoc2netcfg managed entries - DO NOT EDIT THIS BLOCK\n"
            "*/15 * * * * flock ...\n"
            "# END gdoc2netcfg managed entries\n"
        )
        result = add_managed_block("", block)
        assert block in result

    def test_appends_to_existing_crontab(self):
        """Should append block after existing entries."""
        from gdoc2netcfg.cli.cron import add_managed_block

        existing = "0 * * * * other-job\n"
        block = (
            "# BEGIN gdoc2netcfg managed entries - DO NOT EDIT THIS BLOCK\n"
            "*/15 * * * * flock ...\n"
            "# END gdoc2netcfg managed entries\n"
        )
        result = add_managed_block(existing, block)
        assert "0 * * * * other-job" in result
        assert block in result

    def test_replaces_existing_block(self):
        """Should remove old block before adding new one."""
        from gdoc2netcfg.cli.cron import add_managed_block

        existing = (
            "0 * * * * other-job\n"
            "# BEGIN gdoc2netcfg managed entries - DO NOT EDIT THIS BLOCK\n"
            "# OLD ENTRY\n"
            "# END gdoc2netcfg managed entries\n"
        )
        new_block = (
            "# BEGIN gdoc2netcfg managed entries - DO NOT EDIT THIS BLOCK\n"
            "# NEW ENTRY\n"
            "# END gdoc2netcfg managed entries\n"
        )
        result = add_managed_block(existing, new_block)
        assert "OLD ENTRY" not in result
        assert "NEW ENTRY" in result
        assert "0 * * * * other-job" in result
        # Should have exactly one BEGIN marker
        assert result.count("BEGIN gdoc2netcfg") == 1


# ---------------------------------------------------------------------------
# Round-trip integration test
# ---------------------------------------------------------------------------

class TestRoundTrip:
    """Integration test for generate -> format -> add -> remove round-trip."""

    def test_full_round_trip(self):
        """Generating, adding, then removing block should leave crontab intact."""
        from gdoc2netcfg.cli.cron import (
            add_managed_block,
            format_crontab_block,
            generate_cron_entries,
            remove_managed_block,
        )

        existing = "0 * * * * other-job\n30 2 * * * backup\n"
        entries = generate_cron_entries()
        block = format_crontab_block(entries, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))

        # Add the block
        with_block = add_managed_block(existing, block)
        assert "BEGIN gdoc2netcfg" in with_block
        assert "0 * * * * other-job" in with_block

        # Remove the block — original entries should be preserved
        after_remove = remove_managed_block(with_block)
        assert "0 * * * * other-job" in after_remove
        assert "30 2 * * * backup" in after_remove
        assert "BEGIN gdoc2netcfg" not in after_remove

    def test_add_is_idempotent(self):
        """Adding the same block twice should produce the same result."""
        from gdoc2netcfg.cli.cron import (
            add_managed_block,
            format_crontab_block,
            generate_cron_entries,
        )

        existing = "0 * * * * other-job\n"
        entries = generate_cron_entries()
        block = format_crontab_block(entries, Path("/usr/bin/uv"), Path("/opt/gdoc2netcfg"))

        first = add_managed_block(existing, block)
        second = add_managed_block(first, block)
        assert first == second


# ---------------------------------------------------------------------------
# CLI command handlers
# ---------------------------------------------------------------------------

class TestCmdCronShow:
    """Tests for cmd_cron_show()."""

    def test_prints_block_to_stdout(self, capsys):
        """Should print the crontab block to stdout."""
        from gdoc2netcfg.cli.cron import cmd_cron_show

        with (
            patch("shutil.which", return_value="/usr/bin/uv"),
            patch(
                "gdoc2netcfg.cli.cron.detect_project_root",
                return_value=Path("/opt/gdoc2netcfg"),
            ),
        ):
            result = cmd_cron_show()

        assert result == 0
        captured = capsys.readouterr()
        assert "BEGIN gdoc2netcfg" in captured.out
        assert "END gdoc2netcfg" in captured.out
        assert "flock" in captured.out

    def test_prints_detected_paths(self, capsys):
        """Should print detected uv and project root paths."""
        from gdoc2netcfg.cli.cron import cmd_cron_show

        with (
            patch("shutil.which", return_value="/home/tim/.local/bin/uv"),
            patch(
                "gdoc2netcfg.cli.cron.detect_project_root",
                return_value=Path("/opt/gdoc2netcfg"),
            ),
        ):
            cmd_cron_show()

        captured = capsys.readouterr()
        assert "/home/tim/.local/bin/uv" in captured.out
        assert "/opt/gdoc2netcfg" in captured.out


class TestCmdCronInstall:
    """Tests for cmd_cron_install()."""

    def test_installs_block_to_crontab(self, capsys):
        """Should read crontab, add block, write back."""
        from gdoc2netcfg.cli.cron import cmd_cron_install

        with (
            patch("shutil.which", return_value="/usr/bin/uv"),
            patch(
                "gdoc2netcfg.cli.cron.detect_project_root",
                return_value=Path("/opt/gdoc2netcfg"),
            ),
            patch("gdoc2netcfg.cli.cron.read_current_crontab", return_value=""),
            patch("gdoc2netcfg.cli.cron.write_crontab") as mock_write,
        ):
            result = cmd_cron_install()

        assert result == 0
        mock_write.assert_called_once()
        written = mock_write.call_args[0][0]
        assert "BEGIN gdoc2netcfg" in written
        assert "END gdoc2netcfg" in written

    def test_preserves_existing_crontab(self, capsys):
        """Should preserve existing crontab entries when installing."""
        from gdoc2netcfg.cli.cron import cmd_cron_install

        with (
            patch("shutil.which", return_value="/usr/bin/uv"),
            patch(
                "gdoc2netcfg.cli.cron.detect_project_root",
                return_value=Path("/opt/gdoc2netcfg"),
            ),
            patch(
                "gdoc2netcfg.cli.cron.read_current_crontab",
                return_value="0 * * * * other-job\n",
            ),
            patch("gdoc2netcfg.cli.cron.write_crontab") as mock_write,
        ):
            cmd_cron_install()

        written = mock_write.call_args[0][0]
        assert "0 * * * * other-job" in written
        assert "BEGIN gdoc2netcfg" in written


class TestCmdCronUninstall:
    """Tests for cmd_cron_uninstall()."""

    def test_removes_block_from_crontab(self, capsys):
        """Should remove the managed block and write back."""
        from gdoc2netcfg.cli.cron import cmd_cron_uninstall

        existing = (
            "0 * * * * other-job\n"
            "# BEGIN gdoc2netcfg managed entries - DO NOT EDIT THIS BLOCK\n"
            "*/15 * * * * flock ...\n"
            "# END gdoc2netcfg managed entries\n"
        )
        with (
            patch("gdoc2netcfg.cli.cron.read_current_crontab", return_value=existing),
            patch("gdoc2netcfg.cli.cron.write_crontab") as mock_write,
        ):
            result = cmd_cron_uninstall()

        assert result == 0
        mock_write.assert_called_once()
        written = mock_write.call_args[0][0]
        assert "BEGIN gdoc2netcfg" not in written
        assert "0 * * * * other-job" in written

    def test_noop_when_no_block(self, capsys):
        """Should not write crontab when no managed block exists."""
        from gdoc2netcfg.cli.cron import cmd_cron_uninstall

        with (
            patch(
                "gdoc2netcfg.cli.cron.read_current_crontab",
                return_value="0 * * * * other-job\n",
            ),
            patch("gdoc2netcfg.cli.cron.write_crontab") as mock_write,
        ):
            result = cmd_cron_uninstall()

        assert result == 0
        mock_write.assert_not_called()
        captured = capsys.readouterr()
        assert "No gdoc2netcfg" in captured.err

    def test_noop_when_empty_crontab(self, capsys):
        """Should not write crontab when user has no crontab at all."""
        from gdoc2netcfg.cli.cron import cmd_cron_uninstall

        with (
            patch(
                "gdoc2netcfg.cli.cron.read_current_crontab",
                return_value="",
            ),
            patch("gdoc2netcfg.cli.cron.write_crontab") as mock_write,
        ):
            result = cmd_cron_uninstall()

        assert result == 0
        mock_write.assert_not_called()


class TestCmdCron:
    """Tests for cmd_cron() dispatcher."""

    def test_dispatches_to_show(self):
        """Should dispatch to cmd_cron_show when cron_command is 'show'."""
        import argparse

        from gdoc2netcfg.cli.cron import cmd_cron

        args = argparse.Namespace(cron_command="show")
        with (
            patch("gdoc2netcfg.cli.cron.cmd_cron_show", return_value=0) as mock_show,
        ):
            result = cmd_cron(args)
        assert result == 0
        mock_show.assert_called_once()

    def test_dispatches_to_install(self):
        """Should dispatch to cmd_cron_install when cron_command is 'install'."""
        import argparse

        from gdoc2netcfg.cli.cron import cmd_cron

        args = argparse.Namespace(cron_command="install")
        with (
            patch("gdoc2netcfg.cli.cron.cmd_cron_install", return_value=0) as mock_install,
        ):
            result = cmd_cron(args)
        assert result == 0
        mock_install.assert_called_once()

    def test_dispatches_to_uninstall(self):
        """Should dispatch to cmd_cron_uninstall when cron_command is 'uninstall'."""
        import argparse

        from gdoc2netcfg.cli.cron import cmd_cron

        args = argparse.Namespace(cron_command="uninstall")
        with (
            patch("gdoc2netcfg.cli.cron.cmd_cron_uninstall", return_value=0) as mock_uninstall,
        ):
            result = cmd_cron(args)
        assert result == 0
        mock_uninstall.assert_called_once()

    def test_returns_zero_when_no_subcommand(self, capsys):
        """Should print help and return 0 when no cron_command given."""
        import argparse

        from gdoc2netcfg.cli.cron import cmd_cron

        args = argparse.Namespace(cron_command=None)
        result = cmd_cron(args)
        assert result == 0
