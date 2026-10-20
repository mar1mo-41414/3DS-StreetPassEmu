"""The editing model behind the GUI: one TMP Box under construction plus helpers.

Everything the tabs do goes through ``Editor`` so it can be unit-tested without a browser.
The model is a ``BoxSpec`` (tmp_box_builder): loading a box parses it into a spec, keeping
anything the builder does not model verbatim in ``extra_body``, so loading and saving a genuine box
without changing anything reproduces it byte for byte.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import os
import struct
import zlib
from typing import Optional

from .. import icon
from ..mii_random import flags_of, set_birthday, set_flags
from ..mii_qr import (AUTHOR_ID_OFFSET, CHECKSUM_OFFSET, FFL_STORE_DATA_SIZE, MII_ID_OFFSET, NICKNAME_LEN,
                      NICKNAME_OFFSET, crc16_xmodem, new_mii_id)
from ..regions import COUNTRY_JAPAN, JP_PREFECTURES, find_prefecture, prefecture_of_code
from ..smdh import Title, parse_smdh
from ..tmp_box_builder import (COMMENT_MAX_CHARS, HEADER_FIELDS, MII_PLAZA_HMAC_KEY, OFF_MII, BoxSpec,
                               build_message, mii_from_blob_or_raw, spec_from_message)

ICON_KINDS = {"large": icon.LARGE_SIZE, "small": icon.SMALL_SIZE, "header": icon.TLV_SIZE}
NOTICE_MAX_CHARS = 8


class EditorError(ValueError):
    """A user-facing problem (bad input); the message is shown in the UI."""


def png_data_uri(pixels: list[tuple[int, int, int]], size: int, scale: int = 1) -> str:
    """A tiny dependency-free PNG encoder, for previews."""
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            row += bytes(pixels[y * size + x]) * scale
        rows += [bytes(row)] * scale

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    w = size * scale
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, w, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))
    return "data:image/png;base64," + base64.b64encode(png).decode()


def _hex(b: bytes) -> str:
    return b.hex()


class Editor:
    def __init__(self) -> None:
        self.reset()

    # ---- lifecycle -------------------------------------------------------------
    def reset(self) -> None:
        # a fixed messageId / time, so that building twice gives the same box
        self.spec = BoxSpec(mii=b"", message_id=os.urandom(8), created=datetime.datetime.now().replace(microsecond=0))
        self.source = "new"

    def _require_mii(self) -> None:
        if len(self.spec.mii) != FFL_STORE_DATA_SIZE:
            raise EditorError("no_mii")

    # ---- the box ---------------------------------------------------------------
    def load_box(self, data: bytes) -> None:
        if len(data) > 0x14 and struct.unpack_from("<H", data, 0)[0] == 0x6161:
            data = data[0x14:]
        try:
            self.spec = spec_from_message(data)
        except Exception as e:  # noqa: BLE001 - any parse failure is "not a box" for the user
            raise EditorError(f"not_a_box: {e}") from e
        self.source = "loaded"

    def build(self) -> bytes:
        self._require_mii()
        return build_message(self.spec)

    def verify(self) -> dict:
        if len(self.spec.mii) != FFL_STORE_DATA_SIZE:
            return {"built": False}
        msg = build_message(self.spec)
        hsize, bsize = struct.unpack_from("<II", msg, 8)
        body = msg[hsize:hsize + bsize]
        mii_ok = crc16_xmodem(self.spec.mii[:CHECKSUM_OFFSET]) == int.from_bytes(
            self.spec.mii[CHECKSUM_OFFSET:CHECKSUM_OFFSET + 2], "big")
        return {
            "built": True, "size": len(msg),
            "hmac": msg[-32:] == hmac.new(MII_PLAZA_HMAC_KEY, body, hashlib.sha256).digest(),
            "mii_crc": mii_ok,
            "mii_tag": body[OFF_MII:OFF_MII + 112] == _blob(self.spec.mii),
        }

    # ---- Mii -------------------------------------------------------------------
    def set_mii(self, raw: bytes) -> None:
        try:
            self.spec.mii = mii_from_blob_or_raw(raw)
        except ValueError as e:
            raise EditorError(str(e)) from e
        self.spec.mii_id_copy = None

    def set_mii_from_qr(self, image_bytes: bytes) -> None:
        import tempfile
        from ..mii_qr_image import MiiQrError, mii_from_qr_image
        with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as f:
            f.write(image_bytes)
            path = f.name
        try:
            self.spec.mii = mii_from_qr_image(__import__("pathlib").Path(path))
            self.spec.mii_id_copy = None
        except MiiQrError as e:
            raise EditorError(str(e)) from e
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def mii_info(self) -> Optional[dict]:
        m = self.spec.mii
        if len(m) != FFL_STORE_DATA_SIZE:
            return None
        copy, public = flags_of(m)
        return {
            "allow_copy": copy, "public": public,
            "creator": m[0x48:0x5C].decode("utf-16le", "replace").rstrip("\0"),
            "nickname": m[NICKNAME_OFFSET:NICKNAME_OFFSET + NICKNAME_LEN].decode("utf-16le", "replace").rstrip("\0"),
            "author_id": _hex(m[AUTHOR_ID_OFFSET:AUTHOR_ID_OFFSET + 8]),
            "mii_id": _hex(m[MII_ID_OFFSET:MII_ID_OFFSET + 10]),
        }

    def _patch_mii(self, off: int, data: bytes) -> None:
        self._require_mii()
        m = bytearray(self.spec.mii)
        m[off:off + len(data)] = data
        m[CHECKSUM_OFFSET:CHECKSUM_OFFSET + 2] = crc16_xmodem(bytes(m[:CHECKSUM_OFFSET])).to_bytes(2, "big")
        self.spec.mii = bytes(m)
        if off == MII_ID_OFFSET:
            self.spec.mii_id_copy = None

    def set_mii_flags(self, allow_copy=None, public=None) -> None:
        """Edit permission (copy allowed) and sharing of the sender Mii; the checksum is fixed."""
        self._require_mii()
        self.spec.mii = set_flags(self.spec.mii, allow_copy, public)

    def set_ids(self, author_id: Optional[str] = None, mii_id: Optional[str] = None) -> None:
        for name, val, off, n in (("author_id", author_id, AUTHOR_ID_OFFSET, 8), ("mii_id", mii_id, MII_ID_OFFSET, 10)):
            if val:
                try:
                    raw = bytes.fromhex(val)
                except ValueError as e:
                    raise EditorError(f"bad_hex: {name}") from e
                if len(raw) != n:
                    raise EditorError(f"bad_length: {name} {n}")
                self._patch_mii(off, raw)

    def randomize_author_id(self) -> None:
        self._patch_mii(AUTHOR_ID_OFFSET, os.urandom(8))

    def randomize_mii_id(self) -> None:
        self._patch_mii(MII_ID_OFFSET, new_mii_id())

    # ---- text and numbers ------------------------------------------------------
    def set_fields(self, f: dict) -> None:
        s = self.spec
        if "comment" in f:
            if len(f["comment"]) > COMMENT_MAX_CHARS:
                raise EditorError(f"comment_too_long: {COMMENT_MAX_CHARS}")
            s.comment = f["comment"]
        if "notice" in f:
            if len(f["notice"]) > NOTICE_MAX_CHARS:
                raise EditorError(f"notice_too_long: {NOTICE_MAX_CHARS}")
            s.notice = f["notice"]
        if any(k in f for k in ("app_name", "app_long", "app_publisher")):
            cur = (s.titles or [Title("", "", "")])[0]
            name = f.get("app_name", cur.short_description)
            long = f.get("app_long", cur.long_description)
            if "app_long" not in f and cur.long_description in ("", cur.short_description):
                long = name  # the console shows the *long* name; keep it in step with the short one
            s.titles = [Title(name, long, f.get("app_publisher", cur.publisher))]
        for key, attr, lo, hi in (("counter", "visit_counter", 0, 999_999), ("country", "country", 0, 255),
                                  ("region", "region", 0, 255)):
            if key in f:
                v = self._int(f[key], key, lo, hi)
                setattr(s, attr, v)
        if "hobby" in f:
            s.hobby = self._int(f["hobby"], "hobby", 0, 27)
        if "pet" in f:
            s.pet = self._int(f["pet"], "pet", 0, 2)
        if "dream" in f:
            s.dream = self._int(f["dream"], "dream", 0, 19)
        for key, attr in (("app_title_id", "app_title_id"), ("app_title_version", "app_title_version")):
            if key in f:
                try:
                    v = int(str(f[key]), 16)
                except ValueError as e:
                    raise EditorError(f"bad_hex: {key}") from e
                if attr == "app_title_version" and not 0 <= v <= 0xFFFF:
                    raise EditorError(f"out_of_range: {key}")
                setattr(s, attr, v)
        if "prefecture" in f:
            self.set_prefecture(f["prefecture"])
        for key, attr in (("country_ja", 0), ("country_en", 1)):
            if key in f:
                s.country_names = _set_name(s.country_names, attr, f[key])
        for key, attr in (("region_ja", 0), ("region_en", 1)):
            if key in f:
                s.region_names = _set_name(s.region_names, attr, f[key])

    def set_prefecture(self, name: str) -> None:
        """Japan + a prefecture (region code and names); an empty name clears the residence."""
        s = self.spec
        if not name:
            s.country, s.region, s.country_names, s.region_names = 0, 0, None, None
            return
        found = find_prefecture(name)
        if not found:
            raise EditorError(f"unknown_prefecture: {name}")
        code, ja, en = found
        s.country, s.region = COUNTRY_JAPAN, code
        s.country_names, s.region_names = ["日本", "Japan"], [ja, en]

    @staticmethod
    def _int(v, name: str, lo: int, hi: int) -> int:
        try:
            n = int(v)
        except (TypeError, ValueError) as e:
            raise EditorError(f"bad_number: {name}") from e
        if not lo <= n <= hi:
            raise EditorError(f"out_of_range: {name} {lo}-{hi}")
        return n

    # ---- icons -----------------------------------------------------------------
    def set_icon_rgb(self, kind: str, rgb: bytes) -> None:
        """``rgb``: size*size*3 bytes, row-major, already scaled by the browser."""
        if kind not in ICON_KINDS:
            raise EditorError("bad_icon_kind")
        size = ICON_KINDS[kind]
        if len(rgb) != size * size * 3:
            raise EditorError(f"bad_icon_size: {size}")
        data = icon.encode([tuple(rgb[i:i + 3]) for i in range(0, len(rgb), 3)], size)
        setattr(self.spec, {"large": "large_icon", "small": "small_icon", "header": "header_icon"}[kind], data)

    def clear_icon(self, kind: str) -> None:
        if kind not in ICON_KINDS:
            raise EditorError("bad_icon_kind")
        setattr(self.spec, {"large": "large_icon", "small": "small_icon", "header": "header_icon"}[kind], None)

    def load_smdh(self, data: bytes) -> None:
        try:
            smdh = parse_smdh(data)
        except ValueError as e:
            raise EditorError(f"not_smdh: {e}") from e
        self.spec.titles = smdh.titles
        self.spec.small_icon, self.spec.large_icon = smdh.small_icon, smdh.large_icon

    def _icon_preview(self, kind: str) -> Optional[str]:
        data = getattr(self.spec, {"large": "large_icon", "small": "small_icon", "header": "header_icon"}[kind])
        if not data:
            return None
        size = ICON_KINDS[kind]
        return png_data_uri(icon.decode(data, size), size, scale=max(1, 96 // size))

    # ---- message header --------------------------------------------------------
    def header_values(self) -> dict[str, str]:
        raw = build_message(self.spec)[:0x70] if len(self.spec.mii) == FFL_STORE_DATA_SIZE else \
            build_message(BoxSpec(mii=bytes(96), **_header_kwargs(self.spec)))[:0x70]
        return {name: _hex(raw[off:off + n]) for name, off, n in HEADER_FIELDS}

    def set_header(self, values: dict[str, str]) -> None:
        by_name = {n: (o, ln) for n, o, ln in HEADER_FIELDS}
        for name, val in values.items():
            if name not in by_name:
                raise EditorError(f"unknown_field: {name}")
            off, n = by_name[name]
            try:
                raw = bytes.fromhex(val)
            except ValueError as e:
                raise EditorError(f"bad_hex: {name}") from e
            if len(raw) != n:
                raise EditorError(f"bad_length: {name} {n}")
            self.spec.header_fields[off] = raw

    def new_message_ids(self, everything: bool = False) -> None:
        """Fresh messageId and creation time; with ``everything`` also batch / second / sender ids."""
        now = datetime.datetime.now()
        from ..tmp_box_builder import _timestamp
        self.spec.header_fields[0x20] = os.urandom(8)
        self.spec.header_fields[0x60] = _timestamp(now)
        if everything:
            self.spec.header_fields[0x2C] = os.urandom(8)
            self.spec.header_fields[0x18] = os.urandom(4)
            self.spec.header_fields[0x38] = os.urandom(8)
            self.spec.header_fields[0x40] = os.urandom(8)

    # ---- state for the UI --------------------------------------------------------
    def state(self) -> dict:
        s = self.spec
        t = (s.titles or [Title("", "", "")])[0]
        names = lambda lst, i: (lst[i] if lst and i < len(lst) else "")  # noqa: E731
        return {
            "source": self.source,
            "mii": self.mii_info(),
            "comment": s.comment, "notice": s.notice,
            "app_name": t.short_description, "app_long": t.long_description, "app_publisher": t.publisher,
            "app_title_id": f"{s.app_title_id:016x}", "app_title_version": f"{s.app_title_version:04x}",
            "counter": s.visit_counter, "country": s.country, "region": s.region,
            "prefecture": (prefecture_of_code(s.region) or ("",))[0] if s.country == COUNTRY_JAPAN else "",
            "country_ja": names(s.country_names, 0), "country_en": names(s.country_names, 1),
            "region_ja": names(s.region_names, 0), "region_en": names(s.region_names, 1),
            "icons": {k: self._icon_preview(k) for k in ICON_KINDS},
            "header": self.header_values(),
            "extra_body_bytes": sum(len(v) for v in s.extra_body.values()),
            "verify": self.verify(),
            "hobby": s.hobby if s.hobby is not None else (s.comment_header_tail[5] if len(s.comment_header_tail) > 5 else 0),
            "pet": s.pet if s.pet is not None else (s.comment_header_tail[3] if len(s.comment_header_tail) > 3 else 0),
            "dream": s.dream if s.dream is not None else (s.comment_header_tail[4] if len(s.comment_header_tail) > 4 else 0),
            "prefectures": [ja for ja, _en in JP_PREFECTURES],
            "limits": {"comment": COMMENT_MAX_CHARS, "notice": NOTICE_MAX_CHARS},
        }


def _blob(mii: bytes) -> bytes:
    from ..mii_qr import encode_mii_blob
    return encode_mii_blob(mii, recompute_checksum=False)


def _set_name(names: Optional[list[str]], idx: int, value: str) -> list[str]:
    cur = list(names) if names else ["", ""]
    while len(cur) < 2:
        cur.append("")
    cur[idx] = value
    return cur


def _header_kwargs(spec: BoxSpec) -> dict:
    return {"message_id": spec.message_id, "created": spec.created, "header_fields": spec.header_fields}
