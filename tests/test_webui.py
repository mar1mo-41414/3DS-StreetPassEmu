import base64
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from streetpass_emu import icon
from streetpass_emu.mii_qr import crc16_xmodem
from streetpass_emu.smdh import SMDH_SIZE, Title, build_title_table
from streetpass_emu.tmp_box_builder import BoxSpec, build_message
from streetpass_emu.webui import server
from streetpass_emu.webui.editor import Editor, EditorError
from streetpass_emu.webui.runner import RunnerError, keyslot_json_from_aes_keys

def _valid_mii() -> bytes:
    m = bytearray(range(96))
    m[0x5E:0x60] = crc16_xmodem(bytes(m[:0x5E])).to_bytes(2, "big")
    return bytes(m)


MII = _valid_mii()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


@pytest.fixture
def gui(tmp_path):
    app = server.App(Path(__file__).resolve().parent.parent, tmp_path)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = server.make_handler(app, "tok", {f"127.0.0.1:{port}"})
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def call(path, body=None, token="tok", host=None):
        headers = {"X-Token": token}
        if host:
            headers["Host"] = host
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers,
                                     data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.urlopen(req) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if r.headers["Content-Type"].startswith("application/json") else raw)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    yield app, call
    httpd.shutdown()


# ---- Editor -------------------------------------------------------------------------------------
def test_editor_needs_a_mii_before_building():
    e = Editor()
    assert e.state()["verify"] == {"built": False}
    with pytest.raises(EditorError, match="no_mii"):
        e.build()
    e.set_mii(MII)
    assert e.build()[:2] == b"\x60\x60" and e.verify()["hmac"] and e.verify()["mii_tag"]


def test_editor_text_limits():
    e = Editor()
    e.set_fields({"comment": "あ" * 16, "notice": "い" * 8})
    with pytest.raises(EditorError, match="comment_too_long"):
        e.set_fields({"comment": "あ" * 17})
    with pytest.raises(EditorError, match="notice_too_long"):
        e.set_fields({"notice": "い" * 9})
    with pytest.raises(EditorError, match="out_of_range"):
        e.set_fields({"counter": 10_000_000})
    with pytest.raises(EditorError, match="bad_hex"):
        e.set_fields({"app_title_id": "zz"})


def test_loading_and_saving_a_box_is_lossless():
    spec = BoxSpec(mii=MII, comment="こんにちは", extra_body={0x4617: b"\x01\x02\x03", 0x7176: b"\xaa" * 20},
                   header_fields={0x38: bytes(range(8)), 0x6C: b"\x07"})
    box = build_message(spec)
    e = Editor()
    e.load_box(b"\x61\x61" + bytes(0x12) + box)  # received form with the 0x14-byte wrapper
    assert e.build() == box
    assert e.state()["extra_body_bytes"] >= 23


def test_mii_identity_edits_keep_the_mii_valid():
    e = Editor()
    e.set_mii(MII)
    e.set_ids(author_id="0011223344556677", mii_id="9" + "0" * 19)
    assert e.mii_info()["author_id"] == "0011223344556677"
    e.randomize_author_id()
    e.randomize_mii_id()
    v = e.verify()
    assert v["mii_crc"] and v["mii_tag"] and e.mii_info()["mii_id"][0] == "9"
    with pytest.raises(EditorError, match="bad_length"):
        e.set_ids(author_id="00")


def test_icons_and_smdh():
    e = Editor()
    e.set_mii(MII)
    e.set_icon_rgb("small", bytes([10, 20, 30]) * (24 * 24))
    assert e.state()["icons"]["small"].startswith("data:image/png;base64,")
    assert icon.decode(e.spec.small_icon, 24)[0] == icon.unpack565(icon.pack565((10, 20, 30)))
    with pytest.raises(EditorError, match="bad_icon_size"):
        e.set_icon_rgb("large", bytes(5))
    e.clear_icon("small")
    assert e.state()["icons"]["small"] is None
    smdh = bytearray(SMDH_SIZE)
    smdh[:4] = b"SMDH"
    smdh[8:8 + 0x2000] = build_title_table([Title("名前", "", "出版")])
    e.load_smdh(bytes(smdh))
    assert e.state()["app_name"] == "名前" and e.state()["icons"]["large"]
    with pytest.raises(EditorError, match="not_smdh"):
        e.load_smdh(b"nope")


def test_header_fields_and_new_ids():
    e = Editor()
    e.set_mii(MII)
    before = e.header_values()["messageId"]
    e.new_message_ids(everything=True)
    h = e.header_values()
    assert h["messageId"] != before and h["senderId"] != "0" * 16
    e.set_header({"flags": "05"})
    assert e.header_values()["flags"] == "05" and e.build()[0x34] == 5
    with pytest.raises(EditorError, match="bad_length"):
        e.set_header({"flags": "0500"})
    with pytest.raises(EditorError, match="unknown_field"):
        e.set_header({"nope": "00"})


def test_keyslot_json_from_aes_keys_never_needs_both_lines_missing():
    x, y = "00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100"
    out = json.loads(keyslot_json_from_aes_keys(f"slot0x2EKeyX={x}\nslot0x2EKeyY: {y.upper()}\nslot0x30KeyX={x}"))
    assert out == {"key_x": x, "key_y": y}
    with pytest.raises(RunnerError, match="keys_not_found"):
        keyslot_json_from_aes_keys(f"slot0x2EKeyX={x}")


# ---- HTTP -------------------------------------------------------------------------------------
def test_api_requires_token_and_valid_host(gui):
    _app, call = gui
    assert call("/api/state")[0] == 200
    assert call("/api/state", token="wrong")[0] == 403
    assert call("/api/state", host="evil.example:80")[0] == 403


def test_api_edit_flow_and_download(gui):
    app, call = gui
    assert call("/api/box/download")[0] == 400                      # no Mii yet
    st, s = call("/api/mii", {"action": "file", "data": b64(MII)})
    assert st == 200 and s["verify"]["built"]
    st, s = call("/api/fields", {"comment": "やあ", "counter": "12"})
    assert s["comment"] == "やあ" and s["counter"] == 12
    st, err = call("/api/fields", {"comment": "x" * 17})
    assert st == 400 and err["error"].startswith("comment_too_long")
    st, data = call("/api/box/download")
    assert st == 200 and data == app.editor.build()


def test_api_workspace_files_are_confined(gui, tmp_path):
    app, call = gui
    call("/api/mii", {"action": "file", "data": b64(MII)})
    call("/api/files/save", {"name": "../../escape"})
    assert not (tmp_path.parent / "escape.bin").exists() and (tmp_path / "escape.bin").exists()
    call("/api/files/save", {"name": "mii", "what": "mii"})
    names = {f["name"]: f for f in call("/api/files")[1]}
    assert names["mii.bin"]["kind"] == "mii" and names["escape.bin"]["kind"] == "box"
    st, _ = call("/api/files/load", {"name": "../../etc/passwd"})
    assert st == 400


def test_api_icon_and_qr_errors(gui):
    _app, call = gui
    call("/api/mii", {"action": "file", "data": b64(MII)})
    st, s = call("/api/icon", {"kind": "large", "rgb": b64(bytes([200, 0, 0]) * (48 * 48))})
    assert st == 200 and s["icons"]["large"]
    st, err = call("/api/mii", {"action": "qr", "data": b64(b"not an image")})
    assert st == 400 and err["error"]


def test_start_without_setup_gives_a_clear_error(gui):
    _app, call = gui
    call("/api/mii", {"action": "file", "data": b64(MII)})
    st, err = call("/api/run/start", {})
    assert st == 400 and err["error"] in ("no_uv", "no_wifit3", "no_keyslot_file")
    st, s = call("/api/run/stop", {})
    assert st == 200 and s["running"] is False


# ---- settings: friend code and loop options ------------------------------------------------------
def _valid_friend_code() -> str:
    from streetpass_emu.spmtp import principal_id_checksum
    pid = 305419896
    return f"{(principal_id_checksum(pid) << 32) | pid:012d}"


def test_friend_code_is_typed_directly_and_validated(gui, tmp_path):
    app, call = gui
    d = _valid_friend_code()
    st, s = call("/api/settings", {"friend_code": f" {d[:4]} {d[4:8]}{d[8:]} "})
    assert st == 200 and s["settings"]["friend_code"] == f"{d[:4]}-{d[4:8]}-{d[8:]}"
    st, err = call("/api/settings", {"friend_code": "1234-5678-9012"})
    assert st == 400 and err["error"] == "bad_friend_code"
    assert app.runner.settings["friend_code"] == f"{d[:4]}-{d[4:8]}-{d[8:]}"   # the bad one was not stored
    assert call("/api/settings", {"friend_code": ""})[1]["settings"]["friend_code"] == ""


def test_start_builds_the_command_and_friend_code_file(gui, monkeypatch, tmp_path):
    from streetpass_emu.webui import runner as runner_mod
    app, call = gui
    call("/api/mii", {"action": "file", "data": b64(MII)})
    wifit3 = tmp_path / "w3"
    wifit3.mkdir()
    (wifit3 / "pyproject.toml").write_text("")
    keyfile = tmp_path / "k.json"
    keyfile.write_text("{}")
    d = _valid_friend_code()
    call("/api/settings", {"wifit3_dir": str(wifit3), "keyslot_file": str(keyfile), "friend_code": d,
                           "channel": 6, "cycle_seconds": 30, "uv_python": "3.12", "verbose": True, "probe_interval": "5",
                           "match_identity": True, "extra_args": "--outbound-title-id 0x00020800"})
    seen = {}

    class FakeProc:
        stdout = iter(["hello\n"])
        pid = 1

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

    def fake_popen(cmd, **kw):
        seen["cmd"], seen["env"], seen["cwd"] = cmd, kw["env"], kw["cwd"]
        return FakeProc()

    monkeypatch.setattr(runner_mod.shutil, "which", lambda _n: "/usr/bin/uv")
    monkeypatch.setattr(runner_mod.subprocess, "Popen", fake_popen)
    assert call("/api/run/start", {})[0] == 200
    cmd = seen["cmd"]
    assert cmd[:7] == ["uv", "run", "--python", "3.12", "--with", "pycryptodome", "python"] and seen["cwd"] == wifit3
    for flag in ("--verbose", "--match-identity-to-mii", "--probe-interval-seconds", "--outbound-title-id"):
        assert flag in cmd
    assert cmd[cmd.index("--channel") + 1] == "6" and "--fresh-each-cycle" not in cmd
    ff = Path(seen["env"]["STREETPASS_FRIEND_CODE_FILE"])
    assert json.loads(ff.read_text()) == {"friend_code": f"{d[:4]}-{d[4:8]}-{d[8:]}"}
    assert seen["env"]["STREETPASS_KEYSLOT_2E_FILE"] == str(keyfile)


def test_prefecture_sets_codes_and_names():
    from streetpass_emu.regions import find_prefecture
    assert find_prefecture("福岡県")[0] == 41 and find_prefecture("Fukuoka")[0] == 41 and find_prefecture("40")[0] == 41
    assert find_prefecture("福岡")[1] == "福岡県" and find_prefecture("nowhere") is None
    e = Editor()
    e.set_mii(MII)
    e.set_fields({"prefecture": "福岡県"})
    st = e.state()
    assert (st["country"], st["region"], st["prefecture"]) == (1, 41, "福岡県")
    assert (st["country_ja"], st["region_ja"], st["region_en"]) == ("日本", "福岡県", "Fukuoka")
    body = e.build()[0xD14:]
    assert body[0x375C:0x3760] == bytes([0, 0, 41, 1])
    assert body[0x3B60:0x3B60 + 8].decode("utf-16le") == "福岡県\x00"
    e.set_fields({"prefecture": ""})
    assert e.state()["region"] == 0 and e.state()["prefecture"] == ""
    import pytest as _p
    with _p.raises(EditorError, match="unknown_prefecture"):
        e.set_fields({"prefecture": "xx"})


def test_hobby_byte_and_placeholder_icons():
    e = Editor()
    e.set_mii(MII)
    assert e.state()["hobby"] == 0
    e.set_fields({"hobby": 10})
    assert e.build()[0xD14 + 0x3F69] == 10 and e.state()["hobby"] == 10
    with pytest.raises(EditorError, match="out_of_range"):
        e.set_fields({"hobby": 28})
    body = e.build()[0xD14:]
    assert body[0x2038:0x2038 + 1152] != bytes(1152)      # a missing icon is a grey placeholder, not black
