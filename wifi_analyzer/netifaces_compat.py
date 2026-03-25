"""netifaces compatibility wrapper for limited/no-network test environments."""

from __future__ import annotations


class _NetifacesMissing:
    AF_INET = object()

    def interfaces(self):
        return []

    def gateways(self):
        return {}

    def ifaddresses(self, _name):
        return {}


try:  # pragma: no cover
    import netifaces as netifaces  # type: ignore
except Exception:  # pragma: no cover
    netifaces = _NetifacesMissing()
