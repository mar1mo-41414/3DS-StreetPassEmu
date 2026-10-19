# Monitor-Mode RX/TX Layer Notes (wifit3)

> For how to choose a USB Wi-Fi adapter (how to check spoofed-MAC support, and the verified
> hardware table) see [HARDWARE.md](HARDWARE.md).

A summary of what was found by studying `tools/wifit3/` (a clone of
https://github.com/derv82/wifit3, GPLv2). That repository is not committed to this project
(it is excluded by `.gitignore`; it is only kept locally as a reference implementation).

## 1. Architecture highlights

wifit3 has its own "Mini-Driver" layer that drives USB chips directly.

- It is a **port to Python, from C**, of real Linux kernel drivers (ath9k, rtw88, mt76, rt2x00,
  etc.). It accesses the USB chip's registers/firmware directly through PyUSB and **bypasses the
  OS Wi-Fi stack entirely** (avoiding Windows NDIS limits as well as Linux monitor-mode and macOS
  restrictions).
- As a result **the very same code runs on Linux, macOS and Windows**. As the README states, on
  macOS no extra driver is needed as long as you allow the USB device ("Allow").
- Supported chipsets include Atheros AR9271, the MediaTek MT76xx family, the Realtek RTL88xx
  family, Ralink RT chips and so on (see "Supported hardware" in its README). Support is **per
  chipset**, and built-in Wi-Fi does not work (an external USB adapter is required).

→ This is a **direct answer** to the "OS-dependent monitor-mode driver" problem this project wants
to avoid. With a Raspberry Pi or a Mac alike, plugging in a USB adapter with a supported chipset
should run the same Python code.

## 2. Available API (`Driver` ABC in `chips/driver.py`)

Each chip's driver implements the common abstract base class `Driver`, and the StreetPass
implementation can use it as a single "campaign"-like module (the same position as
`campaigns/pmkid.py`, etc.).

Main methods:

- `register_rx_callback(cb: Callable[[Packet], None])`: passes received frames to the callback as
  parsed `Packet`s. The StreetPass state machine watches Probe Requests / Action frames here.
- `await inject_frame(frame_bytes: bytes) -> bool`: transmits one raw 802.11 frame
  (fire-and-forget), leaving ACK waiting to the chip's hardware retransmission.
- `await inject_frame_slow_retry(frame_bytes, timeout=None, max_resends=0)`: a version that waits
  for ACKs and resends in software (needs `enable_rx_acks()`). Looks usable where we must wait for
  the 3DS's response.
- `await set_channel(channel: int, scan: bool=False)`: switch channel.
- `await connect(progress_cb=None)` / `await close()`: bring-up / shutdown.

### ACK-related (important: directly tied to the sequence implementation)

- `enable_rx_acks()` / `record_ack()` / `acks_seen(mac)`: a mechanism that **counts, on the
  receive stream, the peer's ACKs for frames we sent**.
- `enter_active_monitor(mac: bytes, bssid: Optional[bytes]) -> bytes` / `exit_active_monitor()`:
  enable the chip's **hardware auto-ACK** for an arbitrary (spoofed) MAC. The degree of support
  is split by the `FakeMacSupport` enum:
  - `NONE`: impossible
  - `FIXED_MAC`: can only ACK the card's own MAC
  - `SPOOFABLE`: can ACK any spoofed MAC

  → StreetPass requires the PC to impersonate "another 3DS's MAC address" (§4), so **a
  `SPOOFABLE` chip is required**. As recorded on 3dbrew, Probe Response / Action frames are
  likely to need unicast ACKs, which makes this the hardware-dependent branch point.
  Per-chip support is covered in [HARDWARE.md](HARDWARE.md).

## 3. Frame parsing / building

`dot11/packet.py`, `dot11/probe.py`, `dot11/ie.py` and others contain 802.11 frame parsers
(including per-Information-Element parsing). Detecting StreetPass's SSID
`Nintendo_3DS_continuous_scan_000` and recognizing Action frames (category `0x7f`, OUI
`00:1f:32`) can reuse or draw on these. wifit3 itself, however, is specialized for WPA/WEP
cracking, so a parser for the StreetPass Action frame payload structure has to be written
separately.

## 4. Nature of the ported code (caveats)

The README states that the Mini-Driver is "Linux kernel C drivers ported to Python by a coding
agent", built by verifying one instruction at a time while replaying real USB traffic captures
offline. **Each chip is an independent port, and the policy is not to share code between
drivers** (`chips/AGENTS.md`: "don't re-use code from another driver").

→ It looks feasible to layer "StreetPass send/receive logic" thinly on top of an existing chip's
`driver.py` with about the same effort as adding a new chip, but there are hardware-direct
caveats such as **changing the order of register writes can break things (read-modify-write is
not necessarily commutative)** (see `docs/porting/GOTCHAS.md` inside the wifit3 repository).

## 5. License

wifit3 itself is GPL-2.0-only. This project (MIT License) **does not copy wifit3's code**; it only
refers to a separately cloned copy under `tools/wifit3` as an external dependency
(`src/streetpass_emu/driver_bridge.py` defines the parts of wifit3's `WlanInterface` that are
needed as a `Protocol`, and does not depend on wifit3 itself). So no GPL code is included in this
repository. If you import and modify/redistribute wifit3's code, note that that module becomes
subject to GPLv2.
