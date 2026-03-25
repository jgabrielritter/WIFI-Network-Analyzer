from __future__ import annotations

import threading
import time
from typing import Callable

from .scapy_compat import scapy

from .constants import SNIFF_SLICE_SECONDS
from .models import InterfaceInfo, PacketRecord
from .privacy import summarize_endpoint


class PacketCaptureService:
    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    def start(
        self,
        selected: InterfaceInfo,
        on_packet: Callable[[PacketRecord], None],
        on_error: Callable[[str], None],
        redact: bool = True,
    ) -> bool:
        if self._running:
            return False
        self._stop_event.clear()
        self._running = True

        def _worker() -> None:
            try:
                while not self._stop_event.is_set():
                    scapy.sniff(
                        iface=selected.name,
                        timeout=SNIFF_SLICE_SECONDS,
                        store=False,
                        prn=lambda pkt: self._handle_packet(pkt, on_packet, redact),
                        stop_filter=lambda _: self._stop_event.is_set(),
                    )
            except Exception as exc:
                on_error(str(exc))
            finally:
                self._running = False

        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop_event.set()

    def _handle_packet(self, packet: scapy.Packet, on_packet: Callable[[PacketRecord], None], redact: bool) -> None:
        if self._stop_event.is_set() or not packet.haslayer(scapy.IP):
            return
        src, dst = summarize_endpoint(packet[scapy.IP].src, packet[scapy.IP].dst, redact=redact)
        on_packet(
            PacketRecord(
                timestamp=time.strftime("%H:%M:%S"),
                src=src,
                dst=dst,
                protocol=str(packet[scapy.IP].proto),
            )
        )
