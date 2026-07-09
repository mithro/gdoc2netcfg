"""Tests for the CSV cache manager."""

from pathlib import Path

from gdoc2netcfg.sources.cache import CSVCache


class TestCSVCache:
    def test_write_and_read(self, tmp_path: Path):
        cache = CSVCache(tmp_path / "cache")
        cache.write("network", "Machine,MAC Address,IP\ndesktop,aa:bb,10.1.10.1")

        assert cache.has("network")
        content = cache.read("network")
        assert "desktop" in content

    def test_has_missing(self, tmp_path: Path):
        cache = CSVCache(tmp_path / "cache")
        assert not cache.has("nonexistent")

    def test_read_missing_raises(self, tmp_path: Path):
        import pytest

        cache = CSVCache(tmp_path / "cache")
        with pytest.raises(FileNotFoundError):
            cache.read("nonexistent")

    def test_creates_directory(self, tmp_path: Path):
        cache_dir = tmp_path / "nested" / "cache"
        cache = CSVCache(cache_dir)
        cache.write("test", "data")

        assert cache_dir.exists()
        assert cache.read("test") == "data"

    def test_name_sanitization(self, tmp_path: Path):
        cache = CSVCache(tmp_path / "cache")
        cache.write("My Sheet", "data")

        assert cache.has("my_sheet")  # Name is sanitized
        assert cache.read("My Sheet") == "data"  # Original name also works

    def test_overwrite(self, tmp_path: Path):
        cache = CSVCache(tmp_path / "cache")
        cache.write("test", "old data")
        cache.write("test", "new data")

        assert cache.read("test") == "new data"

    def test_unchanged_content_preserves_mtime(self, tmp_path: Path):
        """Rewriting identical content must not touch the file: cache
        mtimes mean 'data last changed' and feed the DNS SOA serials."""
        import os

        cache = CSVCache(tmp_path / "cache")
        cache.write("test", "same data")
        path = tmp_path / "cache" / "test.csv"
        old = 1_700_000_000
        os.utime(path, (old, old))

        cache.write("test", "same data")
        assert int(path.stat().st_mtime) == old

        cache.write("test", "different data")
        assert int(path.stat().st_mtime) != old
        assert cache.read("test") == "different data"
