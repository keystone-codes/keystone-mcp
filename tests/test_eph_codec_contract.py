"""The eph file_id codec's wire contract, which external consumers depend on."""

from keystone_mcp.storage.eph_codec import EPH_PREFIX, unwrap_file_id, wrap_file_id


def test_eph_prefix_is_stable():
    assert EPH_PREFIX == "eph:"


def test_wrap_and_unwrap_roundtrip():
    key = "uploads/auto/2026/06/abc.dat"
    file_id = wrap_file_id(key)
    assert file_id == "eph:uploads/auto/2026/06/abc.dat"
    assert unwrap_file_id(file_id) == key


def test_wrap_produces_the_documented_file_id_shape():
    key = "uploads/ephemeral/2026/06/uuid.dat"
    expected = f"eph:{key}"
    assert wrap_file_id(key) == expected
