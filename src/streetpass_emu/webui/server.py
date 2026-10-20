"""HTTP server for the local web UI: static page + a small JSON API, bound to 127.0.0.1 only.

Protection against other programs / web pages talking to it: a random token (put in the URL that
is opened in the browser and sent as a header with every API call) and a Host header check
(against DNS rebinding). Key material is never sent to the browser.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Optional

from .editor import Editor, EditorError
from .runner import Runner, RunnerError, keyslot_json_from_aes_keys

MAX_BODY = 32 * 1024 * 1024
SAFE_NAME = re.compile(r"[^\w.\-()\[\] ]", re.UNICODE)


def safe_name(name: str, suffix: str = ".bin") -> str:
    n = SAFE_NAME.sub("_", Path(name).name).lstrip(".") or "box"
    return n if n.lower().endswith(suffix) else n + suffix


class App:
    """All state of one GUI session."""

    def __init__(self, repo_root: Path, workspace: Path) -> None:
        self.editor = Editor()
        self.runner = Runner(repo_root, workspace)
        self.workspace = workspace
        self.lock = threading.Lock()

    # ---- file helpers ---------------------------------------------------------------
    def _dirs(self) -> list[Path]:
        return [self.workspace, self.workspace / "received"]

    def files(self) -> list[dict]:
        out = []
        for d in self._dirs():
            for f in sorted(d.glob("*.bin"), key=lambda f: f.stat().st_mtime, reverse=True):
                size = f.stat().st_size
                kind = "box" if size > 20000 else "mii" if size in (96, 112) else "other"
                out.append({"name": f.name, "dir": "received" if d.name == "received" else "", "size": size,
                            "kind": kind, "mtime": int(f.stat().st_mtime)})
        return out

    def _path(self, name: str, folder: str = "") -> Path:
        base = self.workspace / "received" if folder == "received" else self.workspace
        return base / safe_name(name)

    # ---- API ------------------------------------------------------------------
    def handle(self, method: str, path: str, query: dict, body: dict) -> tuple[int, object]:
        """Returns (status, json-able). Raises nothing for expected user errors."""
        e, r = self.editor, self.runner
        try:
            with self.lock:
                if method == "GET" and path == "/api/state":
                    return 200, self.state()
                if method == "GET" and path == "/api/log":
                    return 200, r.log_since(int(query.get("since", ["0"])[0]))
                if method == "GET" and path == "/api/files":
                    return 200, self.files()
                if method == "GET" and path == "/api/doctor":
                    return 200, r.doctor()
                if method != "POST":
                    return 404, {"error": "not_found"}

                if path == "/api/fields":
                    e.set_fields(body)
                elif path == "/api/mii":
                    self._mii(body)
                elif path == "/api/icon":
                    if body.get("clear"):
                        e.clear_icon(body["kind"])
                    else:
                        e.set_icon_rgb(body["kind"], _b64(body["rgb"]))
                elif path == "/api/smdh":
                    e.load_smdh(_b64(body["data"]))
                elif path == "/api/header":
                    if body.get("action") == "new_ids":
                        e.new_message_ids(everything=bool(body.get("everything")))
                    else:
                        e.set_header(body.get("values", {}))
                elif path == "/api/box":
                    self._box(body)
                elif path == "/api/files/load":
                    self._load_file(body)
                elif path == "/api/files/save":
                    self._save_file(body)
                elif path == "/api/settings":
                    r.save_settings(body)
                elif path == "/api/keys/import":
                    self._import_keys(body)
                elif path == "/api/run/start":
                    r.start(e.build())
                elif path == "/api/run/stop":
                    r.stop()
                elif path == "/api/run/help":
                    return 200, {"text": r.loop_help()}
                elif path == "/api/run/adapters":
                    return 200, {"text": r.list_adapters()}
                elif path == "/api/log/clear":
                    r.clear_log()
                else:
                    return 404, {"error": "not_found"}
                return 200, self.state()
        except (EditorError, RunnerError) as ex:
            return 400, {"error": str(ex)}
        except KeyError as ex:
            return 400, {"error": f"missing_field: {ex}"}

    def state(self) -> dict:
        s = self.editor.state()
        s["settings"] = self.runner.settings
        s["running"] = self.runner.running
        s["received"] = self.runner.received()
        s["workspace"] = str(self.workspace)
        return s

    def _mii(self, b: dict) -> None:
        e, a = self.editor, b.get("action")
        if a == "qr":
            e.set_mii_from_qr(_b64(b["data"]))
        elif a == "file":
            e.set_mii(_b64(b["data"]))
        elif a == "clear":
            e.spec.mii = b""
        elif a == "random_author":
            e.randomize_author_id()
        elif a == "random_mii_id":
            e.randomize_mii_id()
        elif a == "set_ids":
            e.set_ids(b.get("author_id"), b.get("mii_id"))
        else:
            raise EditorError("bad_action")

    def _box(self, b: dict) -> None:
        a = b.get("action")
        if a == "new":
            self.editor.reset()
        elif a == "upload":
            self.editor.load_box(_b64(b["data"]))
        else:
            raise EditorError("bad_action")

    def _load_file(self, b: dict) -> None:
        p = self._path(b["name"], b.get("dir", ""))
        if not p.exists():
            raise EditorError("file_not_found")
        data = p.read_bytes()
        if b.get("as") == "mii_from_box":
            tmp = Editor()
            tmp.load_box(data)
            self.editor.spec.mii = tmp.spec.mii
            self.editor.spec.mii_id_copy = None
        elif len(data) in (96, 112) or b.get("as") == "mii":
            self.editor.set_mii(data)
        else:
            self.editor.load_box(data)

    def _save_file(self, b: dict) -> None:
        if b.get("what") == "mii":
            self.editor._require_mii()
            self._path(b["name"]).write_bytes(self.editor.spec.mii)
        else:
            self._path(b["name"]).write_bytes(self.editor.build())

    def _import_keys(self, b: dict) -> None:
        text = _b64(b["data"]).decode("utf-8", "replace")
        out = self.workspace / "streetpass_keyslot_2e.json"
        out.write_text(keyslot_json_from_aes_keys(text), encoding="utf-8")
        try:
            out.chmod(0o600)
        except OSError:
            pass
        self.runner.save_settings({"keyslot_file": str(out)})
        self.runner.log(f"keyslot file written: {out.name}")


def _b64(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=False)
    except Exception as ex:  # noqa: BLE001
        raise EditorError("bad_data") from ex


def make_handler(app: App, token: str, allowed_hosts: set[str]):
    from urllib.parse import parse_qs, urlparse

    index_html = resources.files(__package__).joinpath("static/index.html").read_text(encoding="utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = "StreetPassEmuGUI"

        def log_message(self, fmt, *args):  # keep the console quiet
            pass

        def _host_ok(self) -> bool:
            return (self.headers.get("Host") or "") in allowed_hosts

        def _send(self, status: int, payload, ctype="application/json", extra: Optional[dict] = None) -> None:
            data = payload if isinstance(payload, (bytes, bytearray)) else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text") else ""))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _dispatch(self, method: str) -> None:
            if not self._host_ok():
                return self._send(403, {"error": "bad_host"})
            u = urlparse(self.path)
            q = parse_qs(u.query)
            if u.path == "/favicon.ico":
                return self._send(204, b"", "image/x-icon")
            if method == "GET" and u.path == "/":
                if q.get("t", [""])[0] != token:
                    return self._send(403, b"open the URL printed by the program", "text/plain")
                return self._send(200, index_html.replace("__TOKEN__", token).encode(), "text/html")
            if self.headers.get("X-Token") != token and q.get("t", [""])[0] != token:
                return self._send(403, {"error": "bad_token"})
            if method == "GET" and u.path == "/api/box/download":
                try:
                    data = app.editor.build()
                except EditorError as ex:
                    return self._send(400, {"error": str(ex)})
                return self._send(200, data, "application/octet-stream",
                                  {"Content-Disposition": 'attachment; filename="box.bin"'})
            if method == "GET" and u.path == "/api/mii/download":
                try:
                    app.editor._require_mii()
                except EditorError as ex:
                    return self._send(400, {"error": str(ex)})
                return self._send(200, app.editor.spec.mii, "application/octet-stream",
                                  {"Content-Disposition": 'attachment; filename="mii.bin"'})
            body: dict = {}
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                if n > MAX_BODY:
                    return self._send(413, {"error": "too_large"})
                try:
                    body = json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    return self._send(400, {"error": "bad_json"})
            status, payload = app.handle(method, u.path, q, body)
            self._send(status, payload)

        def do_GET(self):  # noqa: N802
            self._dispatch("GET")

        def do_POST(self):  # noqa: N802
            self._dispatch("POST")

    return Handler


def serve(repo_root: Path, workspace: Path, port: int = 0, open_browser: bool = True) -> None:
    app = App(repo_root, workspace)
    token = secrets.token_urlsafe(18)
    # bind first to learn the port, then build the handler with the matching Host values
    httpd = ThreadingHTTPServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    p = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(app, token, {f"127.0.0.1:{p}", f"localhost:{p}"})
    url = f"http://127.0.0.1:{p}/?t={token}"
    print(f"StreetPassEmu GUI: {url}\n(Ctrl+C to quit; workspace: {workspace})", flush=True)
    if open_browser:
        import webbrowser
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.runner.stop()
        httpd.server_close()
