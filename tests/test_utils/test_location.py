from gdoc2netcfg.utils.location import (
    location_key,
    natural_sort_key,
    parse_location_path,
)


def test_parse_location_path_splits_on_dash():
    assert parse_location_path("Back Shed - Soundproof Rack") == (
        "Back Shed",
        "Soundproof Rack",
    )


def test_parse_location_path_blank_is_empty():
    assert parse_location_path("   ") == ()


def test_location_key_collapses_confusable_spellings():
    assert location_key("Sound Proof Rack") == location_key("Soundproof Rack")
    assert location_key("Back Shed - Soundproof Rack") != location_key("Office")


def test_location_key_separator_insensitive():
    # The exact typo the confusable check exists to catch: a missing space
    # around the ' - ' hierarchy separator must still key to the same place.
    assert location_key("Back Shed - Soundproof Rack") == location_key(
        "Back Shed-Soundproof Rack"
    )


def test_natural_sort_orders_numeric_segments():
    data = ["1/0/11", "1/0/2", "1/0/1"]
    assert sorted(data, key=natural_sort_key) == ["1/0/1", "1/0/2", "1/0/11"]
    assert sorted(["au-plug-10", "au-plug-2"], key=natural_sort_key) == [
        "au-plug-2",
        "au-plug-10",
    ]


def test_natural_sort_handles_no_digits():
    assert natural_sort_key("gi") == natural_sort_key("gi")  # does not raise
    assert sorted(["gi", "1/0/1"], key=natural_sort_key)  # total order, no crash
