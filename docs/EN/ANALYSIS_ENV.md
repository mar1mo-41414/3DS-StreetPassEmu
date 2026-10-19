# Dynamic / Static Analysis Environment Notes (advanced)

Environment notes for going beyond the scope of SETUP.md — investigating unexplained fields or
analyzing a new game.

## 1. Dynamic analysis environment (for re-checking the HMAC key or analyzing new fields)

The HMAC key in [PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md) §8 is already known, but if you
investigate further unexplained fields, the same method (AzaharPlus + GDB) can be used. You need:

- [`AzaharPlus/AzaharPlus`](https://github.com/AzaharPlus/AzaharPlus)
  (plain Azahar and other forks cannot launch encrypted titles directly)
- `gdb-multiarch` (attach to AzaharPlus's built-in gdbstub at `localhost:24689` after
  `set architecture arm`)
- Mii Plaza's encrypted `.app` (under `title/00040010/00020800/content/` on the console's NAND,
  exported with GodMode9 etc.)
- Your console's CFL_DB.dat (`extdata/00048000/f000000b/00000000/00000005`; it can be unpacked
  with `scripts/extract_extdata_file.py` — see [SETUP.md](SETUP.md) §4.3). Placing it at
  AzaharPlus's `nand/data/.../extdata/00048000/F000000B/user/CFL_DB.dat` makes your console's real
  Miis usable in the emulator too

**Important limitation:** AzaharPlus (and the Citra family in general) has no mechanism, by
architecture, to run **system modules such as CECD as LLE (the real console binary as-is)**. The
`lle_applets` setting only applies to "applets" such as the software keyboard, not system modules.
So even if you supply firmware / OTP / SecureInfo etc., CECD's decision logic always remains
AzaharPlus's own HLE reimplementation — to study the real CECD logic you must debug a real
console via Rosalina (§2 of this file).

Supplying OTP / SecureInfo_A / LocalFriendCodeSeed_B / movable.sed is still not wasted (it can
improve Mii rendering accuracy and the behavior of some games). You can place them from a
GodMode9 essential backup like this:

```bash
NAND_DIR=~/.local/share/azaharplus-emu/nand   # on Linux
SYS_DIR=~/.local/share/azaharplus-emu/sysdata
ESSENTIAL=/path/to/gm9backup/essential  # frndseed.bin, otp.bin, secinfo.bin, movable.bin, etc.

mkdir -p "$NAND_DIR/rw/sys" "$NAND_DIR/private"
cp "$ESSENTIAL/secinfo.bin"  "$NAND_DIR/rw/sys/SecureInfo_A"
cp "$ESSENTIAL/frndseed.bin" "$NAND_DIR/rw/sys/LocalFriendCodeSeed_B"
cp "$ESSENTIAL/otp.bin"      "$SYS_DIR/otp.bin"
cp "$ESSENTIAL/movable.bin"  "$NAND_DIR/private/movable.sed"
```

(The paths were confirmed from AzaharPlus's source `src/core/hw/unique_data.cpp`,
`GetSecureInfoAPath()` etc.)

## 2. Dynamic analysis on a real console with Rosalina's built-in GDB

When you want to debug **the real console's actual behavior**, which AzaharPlus's HLE
implementation cannot show (system modules such as CECD always run as AzaharPlus's own
reimplementation, and there is no LLE mechanism in its architecture — `lle_applets` is for
"applets" like the software keyboard and doesn't apply to system modules), you can use the GDB
stub built into Luma3DS's Rosalina menu. This needs a 3DS with CFW.

### Preparation

1. Put the 3DS and the PC on the same LAN (a normal infrastructure Wi-Fi connection is needed,
   separate from the ad-hoc Wi-Fi used for StreetPass)
2. Launch the target application (e.g. Mii Plaza) and get it into a normally operable state
3. Open the Rosalina menu (long-press `L+Down+Select` by default)
4. Choose **Process list** → the target process (Mii Plaza's internal name is `MEET`) →
   **Debug**; a GDB stub starts on the spot and shows the port number it listens on (**not
   fixed — it changes every time**, so check it each time)
5. Connect from the PC:
   ```bash
   gdb-multiarch -q \
     -ex "set architecture arm" \
     -ex "set remotetimeout 30" \
     -ex "set confirm off" \
     -ex "target remote <3DS IP>:<displayed port>" \
     -x breakpoints.txt
   ```

### Known caveats and gotchas

- **Rosalina's debug stub is basically one-shot**: once you connect and GDB disconnects
  (detach / timeout / kill alike), you must start "Debug" again on the same process from the
  Rosalina menu to reconnect. The port number also often changes, so check it at every
  reconnection
- **The "Force-debug next application at launch" feature (default port `4003`) halts completely
  at the entry point (before crt0 runs, all registers 0, PC=0x100000).** From there,
  **`detach` without explicitly sending `continue` crashes the process** (a data abort; no real
  harm to the console, only that process dies). Always end a script with an explicit `continue`
  (not an implicit detach at EOF)
- Attaching to an already running process via the Process list can be re-attached any number of
  times without crashing (the same safe detach as ordinary debugging)
- Liveness check: it's quicker to isolate problems by first checking with `ping <3DS IP>` that
  the 3DS itself is alive and with `nc -zv <IP> <port>` that the port is open
- It's a multithreaded process (Mii Plaza has about 5 threads at startup), so check with
  `info threads` etc. which thread a breakpoint fired on. If register contents differ from what
  you expect, suspect the wrong thread first
- To see IPC command buffer contents, don't guess from raw register values — **disassemble the
  target function correctly in Ghidra first**, then follow the procedure "read the TLS with
  `mrc p15,0,rX,c13,c0,3`, determine the cmdbuf base (= rX itself) from `str rY,[rX,#0x80]!`,
  and read fields at offsets from it". Hand-made capstone traces are error-prone (there is a
  case where register `r0` was misread as the programId, when it was actually a "service handle"
  and the programId was inside `cmdbuf`)
- **If static analysis is blocked by an indirect call through a vtable and you can't tell who
  the caller is, hit a breakpoint and type `bt` (backtrace) to see the runtime call stack
  directly.** This is the go-to approach where static cross-references don't work

### Static analysis with Ghidra (in combination)

```bash
# Decrypt and decompress .code (run in a Python environment that has pyctr)
python3 -c "
from pyctr.type.ncch import NCCHReader
from pyctr.type.exefs import decompress_code
from pyctr.crypto import CryptoEngine
ce = CryptoEngine(boot9='/path/to/boot9.bin')
r = NCCHReader('/path/to/0000001a.app', crypto=ce)  # under the NAND's title/00040010/00020800/content/
with r.exefs.open('.code') as f:
    raw = f.read()
dec = decompress_code(raw)  # an ExeFS .code is often compressed
open('miiplaza.code', 'wb').write(dec)
"

# Create the Ghidra project (the base address is text_addr from the NCCH ExtendedHeader,
# usually 0x00100000)
analyzeHeadless /path/to/project ProjectName \
  -import miiplaza.code -processor "ARM:LE:32:v6" \
  -loader BinaryLoader -loader-baseAddr 0x00100000 -overwrite

# After that, pass a GhidraScript (.java; note that a Jython .py doesn't work unless you
# have a PyGhidra-specific build) with -postScript to disassemble/decompile
```

When extracting Mii Plaza's executable code from a console's NAND backup, **it's a good idea to
compare MD5s between several backups to check whether a version change (an update) actually
happened** (this was checked on two backups one day apart and the code itself was unchanged — but
other content such as the manual had been added, so don't conclude "no update" from the file list
under `content/` alone).
