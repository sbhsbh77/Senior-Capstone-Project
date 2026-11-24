from pyvulscan.scope import assert_in_scope, OutOfScopeError
import pytest


def test_loopback_is_allowed():
    assert assert_in_scope("127.0.0.1") == "127.0.0.1"


def test_private_ranges_allowed():
    assert assert_in_scope("192.168.1.10") == "192.168.1.10"
    assert assert_in_scope("10.0.0.5") == "10.0.0.5"


def test_public_address_is_refused():
    with pytest.raises(OutOfScopeError):
        assert_in_scope("8.8.8.8")


def test_hostname_is_refused():
    with pytest.raises(ValueError):
        assert_in_scope("example.com")
