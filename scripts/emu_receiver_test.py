#!/usr/bin/env python3
"""Feeds a TMP Box to the real Mii Plaza running in AzaharPlus and reports whether it was accepted.

No 3DS needed: the box is dropped into the emulator's CEC InBox (`emu_inject_inbox.py`),
Mii Plaza is launched on a virtual display, and the outcome is judged from

  * a screenshot (an accepted box shows the "today's StreetPass" result screen),
  * the emulator log (a PANIC means the run itself broke),
  * optionally (--trace) guest breakpoints on the receiver functions (needs gdb-multiarch).

Why a watcher thread: AzaharPlus' CECD (an HLE re-implementation) does not recompute the
InBox message count when Mii Plaza deletes the processed message and writes the BoxInfo
header back, so the file ends up "header only, but num_messages=1" and Mii Plaza panics on
the next read. The watcher resets that count to 0 as soon as it sees this state.

The receiver addresses used by --trace are from the *update* build of Mii Plaza (JP).

Usage:
    python scripts/emu_receiver_test.py BOX.bin --azahar PATH/TO/AppRun --app mii_plaza_base.app \
        --baseline DIR [--trace]
"""
from __future__ import annotations

import argparse
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import emu_inject_inbox as inj  # noqa: E402

# receiver functions of the Mii Plaza update build
TRACE_POINTS = {
    0x2BEA4C: "read message header",
    0x2CB1A4: "blocklist check",
    0x2C2538: "sanitize + store",
    0x2C5744: "Mii import",
    0x2C3990: "visitor registration",
}


def inbox_boxinfo(nand: Path, program_id: str) -> Path:
    return nand / inj.CEC_REL / program_id / "InBox___" / "BoxInfo_____"


def watcher(path: Path, stop: threading.Event, fixes: list[float]) -> None:
    t0 = time.time()
    while not stop.is_set():
        try:
            d = path.read_bytes()
            if len(d) == inj.BOXINFO_HDR_LEN and struct.unpack_from("<I", d, 0x14)[0] != 0:
                b = bytearray(d)
                struct.pack_into("<I", b, 0x0C, 0)  # box_size
                struct.pack_into("<I", b, 0x14, 0)  # num_messages
                with open(path, "r+b") as f:
                    f.write(bytes(b))
                fixes.append(time.time() - t0)
        except OSError:
            pass
        time.sleep(0.002)


def restore_baseline(baseline: Path, nand: Path) -> None:
    """Resets the emulator's NAND and Mii Plaza SD data to a saved clean state."""
    root = nand.parent
    shutil.rmtree(nand, ignore_errors=True)
    shutil.copytree(baseline / "nand", nand)
    for ext in (baseline / "sdmc").glob("Nintendo 3DS/*/*/extdata"):
        dst = root / "sdmc" / ext.relative_to(baseline / "sdmc")
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(ext, dst)


def run_trace(port: int, seconds: float) -> list[str]:
    cmds = ["set architecture arm", "set pagination off", f"target remote :{port}"]
    cmds += [f"break *{a:#x}" for a in TRACE_POINTS]
    for _ in range(len(TRACE_POINTS) * 2 + 2):
        cmds += ["continue", "info registers pc"]
    cmds += ["detach", "quit"]
    try:
        out = subprocess.run(["gdb-multiarch", "-q", "-batch", "-ex", "set confirm off"] +
                             sum([["-ex", c] for c in cmds], []),
                             capture_output=True, text=True, timeout=seconds).stdout
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
    hits = []
    for line in out.splitlines():
        if "hit Breakpoint" in line and " in ?? ()" in line:
            addr = int(line.rsplit("0x", 1)[1].split()[0], 16)
            hits.append(TRACE_POINTS.get(addr, hex(addr)))
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("box", type=Path)
    ap.add_argument("--azahar", required=True, type=Path, help="AzaharPlus AppRun / AppImage")
    ap.add_argument("--app", required=True, type=Path, help="Mii Plaza base .app (NCCH)")
    ap.add_argument("--nand", type=Path, default=inj.DEFAULT_NAND)
    ap.add_argument("--log", type=Path, default=Path.home() / ".local/share/azaharplus-emu/log/azahar_log.txt")
    ap.add_argument("--baseline", type=Path,
                    help="directory with nand/ and sdmc/.../extdata saved after a clean first boot; "
                         "restored before each run so earlier runs cannot influence the result")
    ap.add_argument("--display", default=":99", help="virtual display (started with Xvfb if absent)")
    ap.add_argument("--wait", type=float, default=30, help="seconds to run before judging (default 30)")
    ap.add_argument("--shot", type=Path, default=Path("emu_result.png"))
    ap.add_argument("--trace", action="store_true", help="also trace receiver functions via gdbstub")
    ap.add_argument("--gdb-port", type=int, default=24689)
    args = ap.parse_args()

    for tool in ("Xvfb", "import") + (("gdb-multiarch",) if args.trace else ()):
        if not shutil.which(tool):
            raise SystemExit(f"{tool} not found")

    env = dict(os.environ, DISPLAY=args.display)
    xvfb = subprocess.Popen(["Xvfb", args.display, "-screen", "0", "1280x800x24"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    try:
        if args.baseline:
            restore_baseline(args.baseline, args.nand)
        # fresh InBox holding only this box
        subprocess.run([sys.executable, str(Path(__file__).parent / "emu_inject_inbox.py"),
                        str(args.box), "--nand", str(args.nand), "--clear"], check=True,
                       stdout=subprocess.DEVNULL)
        stop, fixes = threading.Event(), []
        th = threading.Thread(target=watcher, args=(inbox_boxinfo(args.nand, "00020800"), stop, fixes),
                              daemon=True)
        th.start()
        emu = subprocess.Popen([str(args.azahar), str(args.app)], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        hits: list[str] = []
        t0 = time.time()
        if args.trace:
            time.sleep(1.5)
            hits = run_trace(args.gdb_port, args.wait)
        time.sleep(max(0, args.wait - (time.time() - t0)))
        subprocess.run(["import", "-window", "root", str(args.shot)], env=env, check=False)
        log = args.log.read_bytes().decode("utf-8", "replace") if args.log.exists() else ""
        panic = "Break reason: PANIC" in log
        stop.set()
        emu.terminate()
        try:
            emu.wait(10)
        except subprocess.TimeoutExpired:
            emu.kill()
    finally:
        xvfb.terminate()

    print(f"InBox count fix-ups : {len(fixes)}")
    print(f"emulator PANIC      : {'YES' if panic else 'no'}")
    if args.trace:
        print("receiver trace      : " + (" -> ".join(hits) if hits else "(no hits)"))
        print(f"registration reached: {'yes' if 'visitor registration' in hits else 'NO'}")
    print(f"screenshot          : {args.shot}")
    return 1 if panic else 0


if __name__ == "__main__":
    raise SystemExit(main())
