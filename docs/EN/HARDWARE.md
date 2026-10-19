# Choosing a USB Wi-Fi Adapter (must read)

**Not every "monitor-mode capable" adapter will work.**
In this project the PC talks to your 3DS while pretending to be *another 3DS's MAC address*.
In 802.11, the receiver of a unicast frame must send an ACK within a very short time (SIFS,
about 10 microseconds), which software cannot do in time. So the adapter (chip) must be able
to do the following in hardware, even for a spoofed MAC:

> **Automatically hardware-ACK frames addressed to an arbitrary (spoofed) MAC address**
> (`FakeMacSupport.SPOOFABLE` in wifit3's code)

With an adapter that cannot (one that only ACKs its own real MAC, or whose support is not
implemented), you may see the Probe Request exchange but the conversation never gets any
further. Built-in Wi-Fi cannot be used either.

## If you are buying a new adapter

**Before buying, check in wifit3's code that the chip is `SPOOFABLE`.** A product page that says
"monitor mode" or "packet injection supported" is not enough to decide.

1. Clone [derv82/wifit3](https://github.com/derv82/wifit3)
2. Look at `FAKE_MAC = FakeMacSupport.XXX` in `src/wifit3/chips/<chip>/driver.py`
   - `SPOOFABLE`: supported (OK to buy)
   - `FIXED_MAC`: only ACKs its own MAC (unusable)
   - `NONE`: impossible in hardware (unusable)
   - `UNIMPLEMENTED`: not ported to wifit3. The silicon may be capable, but it is unusable for now
3. `src/wifit3/chips/products.py` maps product names to chips. Cross-check the product you want
   against it, and against the actual USB ID (`VID:PID` from `lsusb`)
4. Some products ship **different chips depending on the hardware revision** even with the same
   model name. Check the revision / USB ID before buying

Note: even within the same chip family, wifit3 may have separate implementations with different
support. For example `rtl8812au` is `UNIMPLEMENTED` while `rtl8812au_dkms` is `SPOOFABLE`.
Always check the declaration of the implementation that will actually be used.

### Drivers wifit3 declares `SPOOFABLE` (for reference)

As declared at wifit3 commit `45fb760d` (2026-09-07). **Only the two models listed under
"Verified" below have been tested by this project**; the list here is just "wifit3 says so".

`ar9271_v2` / `mt76x0u` / `mt76x2u` / `mt7921au` / `mt7925au` / `rt2800usb` / `rt3070` /
`rt5370` / `rt5372` / `rt5572` / `rtl8188eus_dkms` / `rtl8812au_dkms` / `rtl8814au_dkms` /
`rtl8821au_dkms` / `rtl8821cu_dkms` / `rtl8822bu_dkms` / `rtl8822cu` / `rtl8922au`

Not `SPOOFABLE`: `rt2500usb` (`NONE`), `rtl8187` (`FIXED_MAC`), and `rtl8812au`, `rtl8821au`,
`rtl8188eus`, `rtl8822bu`, `rtw88_8814au` (`UNIMPLEMENTED`).

## Verified / untested

| Adapter | Chip | USB ID | Verified environment |
|---|---|---|---|
| Buffalo WI-U3-866D | RTL8812AU | `0411:025d` | Linux x86_64 |
| Buffalo WI-U2-433DM | RTL8821AU | `0411:0242` | Raspberry Pi 5 (Linux), macOS (Apple Silicon) |

Any other adapter or OS (including Windows) is **untested**. Reports of what did or did not work
are welcome (see "Please do not paste these into Issues" in the [README](../../README.md) first).

## Other requirements

- On Linux you need access to the USB device (see "Running without sudo on Linux" in
  [SETUP.md](SETUP.md)). macOS needs no extra setup
- The target 3DS must be in sleep mode (waiting for StreetPass) with StreetPass Mii Plaza's
  StreetPass enabled
