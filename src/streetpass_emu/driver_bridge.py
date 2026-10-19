"""Wires a wifit3 WlanInterface (docs/MONITOR_MODE.md) to StreetPassResponder
(session.py) so the hardware-independent handshake logic can actually run
against a real monitor-mode-capable Wi-Fi adapter.

Targets ``wifit3.wlan.interface.WlanInterface`` specifically, not the lower
``chips.driver.Driver`` ABC docs/MONITOR_MODE.md otherwise describes: that's
what wifit3's own scripts/campaigns actually build and hand around (see e.g.
scripts/id/scan.py, campaigns/auth_assoc.py), and its method names differ
from the raw Driver's (``send_no_wait`` instead of ``inject_frame``,
``set_fake_mac``/``clear_fake_mac`` instead of ``enter_active_monitor``/
``exit_active_monitor``) -- WlanInterface's register_rx_callback also
supports multiple subscribers, where the raw Driver's does not, which
matters because WlanInterface itself is already subscribed to the driver.

Deliberately does not import wifit3: the slice of WlanInterface this needs
is expressed here as a Protocol, so this stays unit-testable against a small
fake -- no hardware, and no wifit3 install, required to test it.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional, Protocol, runtime_checkable

from .session import StreetPassResponder

logger = logging.getLogger(__name__)


@runtime_checkable
class RawFramePacket(Protocol):
    """The one field this module needs from wifit3's Packet
    (wifit3.dot11.packet.Packet): the raw MPDU bytes, FCS already stripped by
    the driver's RX pipeline (confirmed in e.g. chips/rtl8812au_dkms/driver.py)."""

    raw: bytes


class InjectableInterface(Protocol):
    """The slice of wifit3.wlan.interface.WlanInterface this module drives."""

    def register_rx_callback(self, callback_func: Callable[[RawFramePacket], None]) -> None: ...

    def send_no_wait(self, frame_bytes: bytes) -> Awaitable[bool]: ...

    def set_fake_mac(self, mac: object = None, bssid: object = None) -> Awaitable[Optional[str]]: ...

    def clear_fake_mac(self) -> Awaitable[None]: ...


#: How often to (re-)broadcast our own Probe Request while probing is
#: enabled -- a real console re-sends its continuous-scan Probe Request
#: every ~0.2-0.3s; this project's own outbound
#: broadcast (, 2026-09-15's "we've never played
#: prober" finding) doesn't need to be nearly that aggressive to be useful
#: for testing, so this defaults to a gentler interval instead of hammering
#: the one real peer under test with a fresh probe several times a second.
DEFAULT_PROBE_INTERVAL_SECONDS = 1.0


class StreetPassDriverBridge:
    """Feeds an interface's received frames to a StreetPassResponder and
    injects whatever frame it decides to send back.

    probe_interval_seconds controls the "prober" side: while not None, this project also actively broadcasts its own
    Probe Request on that interval, the same way a real console's own
    continuous scan does, on top of (unconditionally) answering whatever
    probes it back from -- so a real peer whose own scan happens to catch us
    scanning too gets a chance to become our peer *first*, rather than this
    project only ever answering. None (the default) disables this and keeps
    the previous purely-reactive (responder-only) behaviour.
    """

    def __init__(
        self,
        iface: InjectableInterface,
        responder: StreetPassResponder,
        probe_interval_seconds: Optional[float] = None,
    ):
        self.iface = iface
        self.responder = responder
        self.probe_interval_seconds = probe_interval_seconds
        self._queue: "asyncio.Queue[bytes]" = asyncio.Queue()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._task: Optional[asyncio.Task] = None
        self._probe_task: Optional[asyncio.Task] = None

    def _on_packet(self, packet: RawFramePacket) -> None:
        """The interface's RX callback. May fire from a background reader
        thread -- never assume this runs on the asyncio loop's own thread
        (same hazard wifit3's own campaigns/auth_assoc.py handles the same
        way)."""
        if self._loop is None:
            return  # start() hasn't run yet (or stop() already has)
        self._loop.call_soon_threadsafe(self._queue.put_nowait, bytes(packet.raw))

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        assumed = await self.iface.set_fake_mac(mac=self.responder.identity.mac)
        if assumed is None:
            logger.warning("set_fake_mac declined -- this chip can't HW-ACK our chosen identity; "
                            "continuing RX-only (see docs/MONITOR_MODE.md §2, needs FakeMacSupport.SPOOFABLE)")
        self.iface.register_rx_callback(self._on_packet)
        self._task = asyncio.create_task(self._run())
        if self.probe_interval_seconds is not None:
            self._probe_task = asyncio.create_task(self._run_probing())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None
        if self._probe_task is not None:
            self._probe_task.cancel()
            self._probe_task = None
        self._loop = None
        await self.iface.clear_fake_mac()

    async def _run(self) -> None:
        while True:
            frame = await self._queue.get()
            try:
                responses = self.responder.handle_frame(frame)
            except Exception:
                logger.exception("StreetPassResponder.handle_frame raised on a received frame")
                continue
            # Some replies are more than one frame -- e.g. a bare transport
            # ACK immediately followed by our own outgoing data, rather than
            # combining ACK+data into a single packet (project findings
            # §7.9's hypothesis for why a real peer didn't accept that).
            for response in responses:
                await self.iface.send_no_wait(response)

    async def _run_probing(self) -> None:
        """The "prober" side: periodically (re-)broadcast our own Probe
        Request, same as a real console's own continuous scan does, so we
        get a chance to discover a peer ourselves rather than only ever
        answering someone else's broadcast."""
        assert self.probe_interval_seconds is not None
        while True:
            try:
                await self.iface.send_no_wait(self.responder.build_broadcast_probe())
            except Exception:
                logger.exception("failed to send our own broadcast Probe Request")
            await asyncio.sleep(self.probe_interval_seconds)
