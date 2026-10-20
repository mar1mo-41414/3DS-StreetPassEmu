# Checking a box without a console: the Mii Plaza emulator test

You can find out whether Mii Plaza **accepts** a TMP Box without a 3DS and without any Wi-Fi: run
the real Mii Plaza in the AzaharPlus emulator, drop the box into its StreetPass inbox, and watch
what the game does. This is how the "what does a box really need?" question was answered, and it
is the quickest way to test a box built with `scripts/build_tmp_box.py` before it ever goes near
a real console.

## What it tells you, and what it does not

- **It tests Mii Plaza's own receiving code**: header check, blocklist, sanitising of the body,
  Mii import, registration of the visitor. This code runs unmodified in the emulator.
- **It does not test the system service (CECD)**: AzaharPlus re-implements CECD, so message
  authentication (the HMAC trailer) and the radio layer are not exercised. A box can pass here and
  still need a correct HMAC on a real console (`build_tmp_box.py` always computes it).
- It says nothing about how the visitor *looks* beyond what you can see on the emulator screen.

## What you need

(All software for every task is listed in [REQUIREMENTS.md](REQUIREMENTS.md).)

- **AzaharPlus** (the fork that can start encrypted titles directly), on Linux.
- **The Mii Plaza title from your own console**: the base title's `.app` (NCCH) and the SD-card
  update title (`0004000E00020800` for the Japanese version; the receiver addresses used by
  `--trace` are from that update build). Dump them yourself, for example with GodMode9.
- `Xvfb`, ImageMagick (`import`), Python 3.10+; `gdb-multiarch` only for `--trace`.

## One-time setup

1. Put the update title's TMD and content files where AzaharPlus keeps SD titles:
   `<azahar data>/sdmc/Nintendo 3DS/<id0>/<id1>/title/0004000e/00020800/content/`
   (`00000000.tmd` plus the `.app` files, decrypted from the SD layer).
2. Start the base `.app` once (`AzaharPlus <mii_plaza_base.app>`). On the first boot Mii Plaza
   creates its SD data and shows a few dialogs; press A through them until the plaza appears.
   (With the default mapping A is the `S` key.)
3. Close the emulator and **save the state as a baseline**: the emulator's `nand/` directory and
   the `extdata` directory under `sdmc/Nintendo 3DS/<id0>/<id1>/`. The test restores it before
   every run, so earlier visitors or half-finished mini-games cannot change the outcome.
4. To read the guest's behaviour with `--trace`, enable the emulator's GDB stub (port 24689).

## Running a test

```bash
python scripts/emu_receiver_test.py box.bin \
    --azahar /path/to/AppRun-or-AppImage --app mii_plaza_base.app \
    --baseline /path/to/baseline --trace
```

It restores the baseline, puts the box into the CEC inbox (`scripts/emu_inject_inbox.py`),
starts the emulator on a virtual display, waits, takes a screenshot and prints a summary.

| Result | Screen | `--trace` |
|---|---|---|
| **Accepted** | "今回のすれちがい N回 やった!!" (today's StreetPass: N) | `read header → blocklist → read header → sanitize → Mii import → blocklist → visitor registration` |
| **Rejected** (e.g. one byte of the Mii's CCM tag changed) | an unrelated dialog ("ところで…") | stops after `read header` |

A genuine box is accepted; the same box with a broken Mii tag is silently dropped, just like on a
real console (a green light but no visitor in the plaza).

## Finding the minimum a box needs: `emu_bisect_box.py`

```bash
python scripts/emu_bisect_box.py genuine_box.bin --azahar ... --app ... --baseline ... [--combine]
```

zeroes one body region at a time (titles, icons, country/region tables, comment, the
console-specific records, the statistics tail, the residence code) and reports ACCEPT / reject for
each. Result with a genuine box: **every region could be zeroed on its own, and a box in which
everything except the first 0x30 bytes of the body and the sender Mii was zero was still
accepted.** See [PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) for the body map.

## Why the test has a watcher thread

When Mii Plaza has processed a message it deletes the inbox and writes the 0x20-byte header of
`InBox___/BoxInfo_____` back with the *old* message count. A real CECD fixes the count; the
emulator's does not, so the file ends up "header only, but 1 message" and the game panics on its
next read (`svcBreak`, result `0xC8E1086A` from its own consistency check). The test script
watches the file and resets the count to 0 within a few milliseconds. Without it, any box that is
accepted still crashes the emulated game a moment later.

## Limits

- The receiver trace addresses are for one build (the Japanese update); other regions need their
  own addresses, but the screenshot check works unchanged.
- **Acceptance and dialogue differ from a real console in details.** Acceptance has matched every real-console test so far, but the
  arrival conversation does not: the emulator shows the comment and the hobby line at once at a first meeting, while a real console
  showed one or two profile lines (never the comment) and one conversation per Mii per day.
- Visitor *rendering* in the emulator uses open-source stand-ins for the shared Mii data and
  fonts, so faces appear as placeholders. Judge acceptance, not appearance.
