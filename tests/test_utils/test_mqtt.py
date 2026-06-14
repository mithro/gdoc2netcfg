"""Tests for the MQTT-safe identity transform."""

from gdoc2netcfg.utils.mqtt import node_id


class TestNodeId:
    def test_dashes_to_underscores(self):
        assert node_id("big-storage") == "big_storage"

    def test_dotted_bmc_distinct_from_parent(self):
        assert node_id("bmc.big-storage") == "bmc_big_storage"

    def test_plain_unchanged(self):
        assert node_id("my_host") == "my_host"

    def test_lowercased(self):
        assert node_id("MyHost") == "myhost"

    def test_multi_dot(self):
        assert node_id("sw.rack-1.unit-2") == "sw_rack_1_unit_2"
