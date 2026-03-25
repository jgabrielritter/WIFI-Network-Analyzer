"""Scapy compatibility wrapper so tests can run without scapy installed."""

from __future__ import annotations


class _ScapyMissing:
    class IP:  # pragma: no cover
        pass

    class Packet:  # pragma: no cover
        pass

    @staticmethod
    def sniff(*_args, **_kwargs):  # pragma: no cover
        raise RuntimeError("Scapy is required for packet capture features.")

    @staticmethod
    def srp(*_args, **_kwargs):  # pragma: no cover
        raise RuntimeError("Scapy is required for ARP scan features.")

    @staticmethod
    def ARP(*_args, **_kwargs):  # pragma: no cover
        raise RuntimeError("Scapy is required for ARP scan features.")

    @staticmethod
    def Ether(*_args, **_kwargs):  # pragma: no cover
        raise RuntimeError("Scapy is required for ARP scan features.")


try:  # pragma: no cover - exercised via runtime availability
    import scapy.all as scapy  # type: ignore
except Exception:  # pragma: no cover
    scapy = _ScapyMissing()
