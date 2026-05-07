import pytest

from driftmux.utils import collect_scan_hosts, expand_targets, split_csv_values


def test_split_csv_values():
    assert split_csv_values("a,b, c") == ["a", "b", "c"]


def test_expand_single_ip():
    assert expand_targets("192.168.1.10") == ["192.168.1.10"]


def test_expand_cidr():
    assert expand_targets("192.168.1.0/30") == [
        "192.168.1.1",
        "192.168.1.2",
    ]


def test_expand_hostname():
    assert expand_targets("example.org") == ["example.org"]


def test_collect_scan_hosts_from_host():
    assert collect_scan_hosts(host="example.org") == ["example.org"]


def test_collect_scan_hosts_from_targets():
    assert collect_scan_hosts(
        targets="192.168.1.10,192.168.1.11,example.org"
    ) == [
        "192.168.1.10",
        "192.168.1.11",
        "example.org",
    ]


def test_collect_scan_hosts_from_cidr_targets():
    assert collect_scan_hosts(targets="192.168.1.0/30") == [
        "192.168.1.1",
        "192.168.1.2",
    ]


def test_collect_scan_hosts_deduplicates():
    assert collect_scan_hosts(
        host="example.org",
        targets="example.org,192.168.1.10",
    ) == [
        "example.org",
        "192.168.1.10",
    ]


def test_collect_scan_hosts_requires_input():
    with pytest.raises(ValueError):
        collect_scan_hosts()


def test_expand_too_large():
    with pytest.raises(ValueError):
        expand_target("192.168.0.0/16", max_hosts=256)
