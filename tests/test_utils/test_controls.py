from gdoc2netcfg.utils.controls import parse_controls_cell, strip_interface_prefix


def test_parse_controls_comma_and_newline():
    assert parse_controls_cell("desktop, monitor\nserver\r\nac") == (
        "desktop", "monitor", "server", "ac",
    )


def test_parse_controls_empty():
    assert parse_controls_cell("") == ()
    assert parse_controls_cell("  \n ,") == ()


def test_strip_interface_prefix_eth():
    assert strip_interface_prefix("eth0.rpi5-pmod") == ("eth0", "rpi5-pmod")


def test_strip_interface_prefix_slot_port():
    assert strip_interface_prefix("1/0/49.sw-cisco-shed") == ("1/0/49", "sw-cisco-shed")


def test_strip_interface_prefix_none():
    assert strip_interface_prefix("desktop") == ("", "desktop")
