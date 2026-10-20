#!/usr/bin/env python3
"""Starts the local web GUI and opens it in your browser (Windows / macOS / Linux).

    python scripts/gui.py [--workspace DIR] [--port N] [--no-browser]

The server listens on 127.0.0.1 only. Boxes, Miis and received messages are kept in the workspace
folder (default ./workspace, git-ignored). Needs nothing beyond the project's own requirements.
"""
import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from streetpass_emu.webui.server import serve  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", type=Path, default=Path("workspace"))
    ap.add_argument("--port", type=int, default=0, help="0 = pick a free port")
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    serve(REPO, a.workspace.resolve(), a.port, not a.no_browser)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
