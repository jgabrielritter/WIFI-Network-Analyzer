import pytest

from wifi_analyzer.interfaces import discover_interfaces, resolve_interface_network
from wifi_analyzer.models import InterfaceInfo


def test_resolve_interface_network_success():
    iface = InterfaceInfo(name="eth0", display_name="eth0", ipv4="192.168.1.12", netmask="255.255.255.0")
    network = resolve_interface_network(iface)
    assert str(network) == "192.168.1.0/24"


def test_resolve_interface_network_missing_ipv4():
    iface = InterfaceInfo(name="eth0", display_name="eth0", ipv4=None, netmask="255.255.255.0")
    with pytest.raises(RuntimeError, match="no IPv4"):
        resolve_interface_network(iface)


def test_resolve_interface_network_missing_netmask():
    iface = InterfaceInfo(name="eth0", display_name="eth0", ipv4="10.0.0.2", netmask=None)
    with pytest.raises(RuntimeError, match="missing a netmask"):
        resolve_interface_network(iface)


def test_discover_interfaces_returns_list():
    assert isinstance(discover_interfaces(), list)
