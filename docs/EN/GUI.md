# The GUI (works on Windows, macOS and Linux)

```bash
python scripts/gui.py
```

starts a small local web server and opens it in your browser. It needs nothing beyond the project's
own requirements (no extra packages, no Electron, no Tk) and looks the same on every OS. It listens on
`127.0.0.1` only; the URL it prints contains a one-time token, so other programs and web pages cannot
use it. Quit with Ctrl+C. Options: `--workspace DIR` (default `./workspace`, git-ignored), `--port N`,
`--no-browser`.

Everything you create lives in the **workspace** folder: boxes you saved, Miis, received messages
(`received/`), and the settings (paths and numbers only — never key values). Treat it as personal data.
The language (Japanese / English) can be switched at the top right.

## Tabs

| Tab | What it does |
|---|---|
| **Send / Receive** | Starts and stops the StreetPass loop (`scripts/streetpass_loop.py`) with the Box you are editing, shows the setup check, lists adapters, keeps the settings (channel, listening time, key file, ...), and lists the boxes you received (use their Mii, or open them for editing). |
| **Mii** | Chooses the sender Mii: from a **Mii QR code image** (Mii Maker → "Send Miis"), from a 96-byte / 112-byte Mii file, or from a received box. Shows nickname and IDs, saves the Mii file. |
| **Box** | The greeting comment (16 characters), notification text (8), the "last app that set the Mii" (name, title ID, version, or load an **SMDH file**), counter, country / region, and the three icons (images are scaled in the browser). |
| **Identity** | The Mii's `author_id` / `mii_id` (set, or make new ones — CRC16 and the AES-CCM tag are rebuilt automatically) and every field of the message header (messageId, times, flags, ...), with one-click "new IDs". |
| **Files** | Start from an empty box, open a box file, download or save the current box, browse the workspace, and see the checks (HMAC, Mii CRC16, Mii tag). Opening a genuine box keeps everything the editor does not model, so saving it unchanged gives back the same bytes. |
| **Log** | Output of the send / receive loop. |

A box can be built from scratch: choose a Mii, edit the text, and use it. You do not need a received
box as a template.

## What the Send / Receive tab needs

The GUI does not replace the Wi-Fi driver setup; it starts the same command you would type. You still
need ([REQUIREMENTS.md](REQUIREMENTS.md), [SETUP.md](SETUP.md)):

- `wifit3` checked out (default folder `tools/wifit3`) and `uv` installed,
- a USB Wi-Fi adapter that can ACK a spoofed MAC ([HARDWARE.md](HARDWARE.md)) and, on Linux, the udev
  rule or `sudo`,
- the keyslot 0x2E key file. Pick the `aes_keys.txt` you dumped with GodMode9 in the settings and the GUI
  extracts the two needed lines into a JSON file in the workspace (the values are never shown).

**Friend code (optional)**: type the 12 digits shown on the console's friend list screen straight into the
settings (dashes optional). The GUI checks the checksum — a typo is refused — and writes the file the loop
needs itself. Left empty, the PC answers "not a friend".

**Advanced settings** (folded away; the defaults are fine): log every frame, pause between cycles, start-up
retries, actively searching every N seconds like a real console, matching the Wi-Fi-layer identity to the
sender Mii (experimental), and regenerating the IDs every cycle. **Other options** is a free field whose
text is passed to `scripts/streetpass_loop.py` unchanged, for options the switches do not cover (for example
`--outbound-title-id 0x00020800`); "Show the available options" prints the full list. Normally leave it empty.

"Check setup" tells you which of these is missing; "Check adapters" asks wifit3 which supported adapters
it can see. The editing tabs work without any of this.

## Limits

- The Mii is shown by nickname and IDs only; rendering its face needs the console's own Mii renderer.
- Start / Stop drives real hardware and has been verified on the maintainer's setup only; other OSes and
  adapters are untested (see [STATUS.md](STATUS.md)).
- Do not paste screenshots or logs of the GUI into issues if they show IDs or file names from your console.
