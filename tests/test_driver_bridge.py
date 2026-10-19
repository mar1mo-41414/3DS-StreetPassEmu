import asyncio
from dataclasses import dataclass, field
from typing import List, Optional

from streetpass_emu import dot11
from streetpass_emu.driver_bridge import StreetPassDriverBridge
from streetpass_emu.session import SessionIdentity, StreetPassResponder

# Same real StreetPass Probe Request capture used elsewhere.
_CAPTURE_ROWS = [
    "00 00 1a 00 2f 48 00 00 19 7d 19 de 2a 00 00 00",
    "12 16 9e 09 a0 00 c9 02 00 00 40 00 00 00 ff ff",
    "ff ff ff ff da 6b f7 22 f3 77 ff ff ff ff ff ff",
    "40 77 00 20 4e 69 6e 74 65 6e 64 6f 5f 33 44 53",
    "5f 63 6f 6e 74 69 6e 75 6f 75 73 5f 73 63 61 6e",
    "5f 30 30 30 01 08 82 84 8b 0c 12 96 18 24 32 04",
    "30 48 60 6c dd 15 00 1f 32 01 11 05 00 02 08 00",
    "00 f0 08 c8 34 6e 05 0f c9 c6 80 5b 6f bc 5a",
]
CAPTURED_FRAME = bytes.fromhex("".join(_CAPTURE_ROWS))
PEER_MAC = bytes.fromhex("da6bf722f377")


def _peer_broadcast_probe_request() -> bytes:
    """The real captured frame with radiotap and FCS stripped -- matching
    what a wifit3 WlanInterface's Packet.raw actually carries (no radiotap
    ever reaches Packet.raw; FCS is stripped by the driver's RX walk)."""
    return CAPTURED_FRAME[dot11.radiotap_header_length(CAPTURED_FRAME):-4]


@dataclass
class _FakePacket:
    raw: bytes


@dataclass
class _FakeInterface:
    injected_frames: List[bytes] = field(default_factory=list)
    fake_mac_set: Optional[bytes] = None
    fake_mac_cleared: bool = False
    _rx_callback: Optional[callable] = None

    def register_rx_callback(self, callback_func) -> None:
        self._rx_callback = callback_func

    async def send_no_wait(self, frame_bytes: bytes) -> bool:
        self.injected_frames.append(frame_bytes)
        return True

    async def set_fake_mac(self, mac=None, bssid=None):
        self.fake_mac_set = mac
        return ":".join(f"{b:02x}" for b in mac) if mac is not None else None

    async def clear_fake_mac(self) -> None:
        self.fake_mac_cleared = True

    def deliver(self, raw: bytes) -> None:
        """Simulate the driver's RX reader firing the callback."""
        assert self._rx_callback is not None, "register_rx_callback was never called"
        self._rx_callback(_FakePacket(raw=raw))


def _responder() -> StreetPassResponder:
    identity = SessionIdentity(console_id=bytes.fromhex("0011223344556677"), mac=bytes.fromhex("222222222222"))
    return StreetPassResponder(identity=identity, services=[bytes.fromhex("0002080000")])


def test_start_arms_fake_mac_and_registers_callback():
    async def body():
        iface = _FakeInterface()
        bridge = StreetPassDriverBridge(iface, _responder())

        await bridge.start()

        assert iface.fake_mac_set == bridge.responder.identity.mac
        assert iface._rx_callback is not None

    asyncio.run(body())


def test_a_real_broadcast_probe_request_gets_a_probe_response_injected():
    async def body():
        iface = _FakeInterface()
        bridge = StreetPassDriverBridge(iface, _responder())
        await bridge.start()

        iface.deliver(_peer_broadcast_probe_request())
        await asyncio.sleep(0.05)  # let the background _run() task drain the queue

        assert len(iface.injected_frames) == 1
        response = dot11.parse_probe_response(iface.injected_frames[0])
        assert response.header.addr1 == PEER_MAC
        assert response.header.addr2 == bridge.responder.identity.mac
        assert bridge.responder.peers[PEER_MAC].value == "discovered"

    asyncio.run(body())


def test_irrelevant_frames_are_not_answered():
    async def body():
        iface = _FakeInterface()
        bridge = StreetPassDriverBridge(iface, _responder())
        await bridge.start()

        iface.deliver(bytes(30))  # not a Probe Request StreetPass cares about
        await asyncio.sleep(0.05)

        assert iface.injected_frames == []

    asyncio.run(body())


def test_stop_clears_fake_mac_and_cancels_the_run_task():
    async def body():
        iface = _FakeInterface()
        bridge = StreetPassDriverBridge(iface, _responder())
        await bridge.start()

        await bridge.stop()

        assert iface.fake_mac_cleared is True
        assert bridge._task is None

    asyncio.run(body())


def test_a_malformed_frame_does_not_crash_the_run_loop():
    """handle_frame() raising shouldn't kill the background task -- the next
    good frame must still get a response."""
    async def body():
        iface = _FakeInterface()
        bridge = StreetPassDriverBridge(iface, _responder())
        await bridge.start()

        iface.deliver(b"\x00")  # too short for parse_management_header -> ValueError, caught
        iface.deliver(_peer_broadcast_probe_request())
        await asyncio.sleep(0.05)

        assert len(iface.injected_frames) == 1

    asyncio.run(body())


def test_probe_interval_none_never_broadcasts_on_its_own():
    """Default (purely-reactive) behaviour must be unchanged: no probing
    task at all when probe_interval_seconds is left at its default None."""
    async def body():
        iface = _FakeInterface()
        bridge = StreetPassDriverBridge(iface, _responder())
        await bridge.start()

        await asyncio.sleep(0.05)

        assert bridge._probe_task is None
        assert iface.injected_frames == []

    asyncio.run(body())


def test_probe_interval_set_broadcasts_our_own_probe_request_periodically():
    async def body():
        iface = _FakeInterface()
        bridge = StreetPassDriverBridge(iface, _responder(), probe_interval_seconds=0.01)
        await bridge.start()

        await asyncio.sleep(0.05)  # several intervals' worth

        assert len(iface.injected_frames) >= 2
        for frame in iface.injected_frames:
            probe = dot11.parse_probe_request(frame)
            assert probe.header.addr2 == bridge.responder.identity.mac
            assert probe.header.addr1 == dot11.BROADCAST_MAC

        await bridge.stop()

    asyncio.run(body())


def test_stop_cancels_the_probe_task_too():
    async def body():
        iface = _FakeInterface()
        bridge = StreetPassDriverBridge(iface, _responder(), probe_interval_seconds=0.01)
        await bridge.start()
        assert bridge._probe_task is not None

        await bridge.stop()

        assert bridge._probe_task is None

    asyncio.run(body())
