"""Runs the StreetPass send/receive loop (scripts/streetpass_loop.py) as a child process.

The loop needs the Wi-Fi driver (wifit3, a separate checkout managed with ``uv``), so it is started
with ``uv run`` inside that directory, exactly like the command line instructions. This module only
builds the command, streams its output into the GUI log and stops it again; it never reads key files.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Optional

LOG_LINES = 4000
SETTINGS_FILE = "settings.json"
DEFAULT_SETTINGS = {
    "wifit3_dir": "tools/wifit3",
    "keyslot_file": "",
    "friend_code_file": "",
    "channel": 1,
    "cycle_seconds": 120,
    "cycles": 0,
    "fresh_each_cycle": False,
    "extra_args": "",
    "lang": "",
}


class RunnerError(RuntimeError):
    """A user-facing problem; the message starts with a code the UI translates."""


class Runner:
    def __init__(self, repo_root: Path, workspace: Path) -> None:
        self.repo = repo_root
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        (self.workspace / "received").mkdir(exist_ok=True)
        self._log: deque[tuple[int, str]] = deque(maxlen=LOG_LINES)
        self._seq = 0
        self._lock = threading.Lock()
        self._proc: Optional[subprocess.Popen] = None
        self.settings = dict(DEFAULT_SETTINGS)
        self.load_settings()

    # ---- settings (paths and numbers only; never key material) -------------------------------
    def load_settings(self) -> None:
        try:
            self.settings.update(json.loads((self.workspace / SETTINGS_FILE).read_text()))
        except (OSError, ValueError):
            pass

    def save_settings(self, new: dict) -> None:
        for k in DEFAULT_SETTINGS:
            if k in new:
                self.settings[k] = new[k]
        (self.workspace / SETTINGS_FILE).write_text(json.dumps(self.settings, ensure_ascii=False, indent=2))

    # ---- log ----------------------------------------------------------------------
    def log(self, line: str) -> None:
        with self._lock:
            self._seq += 1
            self._log.append((self._seq, time.strftime("%H:%M:%S ") + line.rstrip("\n")))

    def log_since(self, since: int) -> dict:
        with self._lock:
            return {"next": self._seq, "lines": [l for s, l in self._log if s > since]}

    def clear_log(self) -> None:
        with self._lock:
            self._log.clear()

    # ---- helpers --------------------------------------------------------------------
    def _wifit3(self) -> Path:
        p = Path(self.settings["wifit3_dir"]).expanduser()
        return p if p.is_absolute() else (self.repo / p)

    def _env(self) -> dict:
        env = dict(os.environ)
        if self.settings["keyslot_file"]:
            env["STREETPASS_KEYSLOT_2E_FILE"] = str(Path(self.settings["keyslot_file"]).expanduser())
        if self.settings["friend_code_file"]:
            env["STREETPASS_FRIEND_CODE_FILE"] = str(Path(self.settings["friend_code_file"]).expanduser())
        return env

    def doctor(self) -> list[dict]:
        """Checks of everything the send/receive tab depends on. Values of keys are never shown."""
        w = self._wifit3()
        out = []

        def add(name: str, ok: bool, detail: str = "") -> None:
            out.append({"name": name, "ok": ok, "detail": detail})

        add("uv", shutil.which("uv") is not None, shutil.which("uv") or "")
        add("wifit3", (w / "pyproject.toml").exists(), str(w))
        add("loop_script", (self.repo / "scripts" / "streetpass_loop.py").exists())
        for key, label in (("keyslot_file", "keyslot_file"), ("friend_code_file", "friend_code_file")):
            v = self.settings[key]
            add(label, bool(v) and Path(v).expanduser().exists(), "" if not v else Path(v).name)
        return out

    def list_adapters(self) -> str:
        """Asks wifit3 which supported USB Wi-Fi adapters are plugged in."""
        w = self._wifit3()
        if not shutil.which("uv"):
            raise RunnerError("no_uv")
        if not (w / "pyproject.toml").exists():
            raise RunnerError("no_wifit3")
        p = subprocess.run(["uv", "run", "python", "-c",
                            "from wifit3.device.manager import wlan_ifaces; print(wlan_ifaces())"],
                           cwd=w, capture_output=True, text=True, timeout=180)
        return (p.stdout + p.stderr).strip()

    # ---- the loop --------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, box_bytes: bytes) -> None:
        if self.running:
            raise RunnerError("already_running")
        s = self.settings
        w = self._wifit3()
        if not shutil.which("uv"):
            raise RunnerError("no_uv")
        if not (w / "pyproject.toml").exists():
            raise RunnerError("no_wifit3")
        if not s["keyslot_file"] or not Path(s["keyslot_file"]).expanduser().exists():
            raise RunnerError("no_keyslot_file")
        box = self.workspace / "outbound.bin"
        box.write_bytes(box_bytes)
        cmd = ["uv", "run", "python", str(self.repo / "scripts" / "streetpass_loop.py"),
               "--channel", str(int(s["channel"])), "--cycle-seconds", str(float(s["cycle_seconds"])),
               "--cycles", str(int(s["cycles"])), "--out-dir", str(self.workspace / "received"),
               "--outbound-tmp-box-body-template", str(box)]
        if s["fresh_each_cycle"]:
            cmd.append("--fresh-each-cycle")
        if s["extra_args"].strip():
            import shlex
            cmd += shlex.split(s["extra_args"])
        self.log("$ " + " ".join(cmd))
        kwargs = {"start_new_session": True} if os.name != "nt" else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        self._proc = subprocess.Popen(cmd, cwd=w, env=self._env(), stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True, bufsize=1, **kwargs)
        threading.Thread(target=self._pump, args=(self._proc,), daemon=True).start()

    def _pump(self, proc: subprocess.Popen) -> None:
        assert proc.stdout
        for line in proc.stdout:
            self.log(line)
        code = proc.wait()
        self.log(f"[exit code {code}]")

    def stop(self) -> None:
        p = self._proc
        if not p or p.poll() is not None:
            return
        self.log("[stopping]")
        try:
            if os.name == "nt":
                p.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(os.getpgid(p.pid), signal.SIGINT)
            p.wait(timeout=15)
        except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
            p.kill()

    def received(self) -> list[dict]:
        d = self.workspace / "received"
        return [{"name": f.name, "size": f.stat().st_size, "mtime": int(f.stat().st_mtime)}
                for f in sorted(d.glob("*.bin"), key=lambda f: f.stat().st_mtime, reverse=True)]


_KEY_RE = re.compile(r"slot0x2EKey([XY])\s*[=:]\s*([0-9A-Fa-f]{32})")


def keyslot_json_from_aes_keys(text: str) -> str:
    """Builds the keyslot 0x2E JSON (SETUP.md §4.2) from the contents of GodMode9's aes_keys.txt."""
    found = {m.group(1): m.group(2).lower() for m in _KEY_RE.finditer(text)}
    if set(found) != {"X", "Y"}:
        raise RunnerError("keys_not_found")
    return json.dumps({"key_x": found["X"], "key_y": found["Y"]}, indent=2)
