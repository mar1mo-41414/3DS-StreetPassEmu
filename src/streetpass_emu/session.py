"""Our own StreetPass identity, and the responder state machine that decides
what to send back for an incoming frame.

Deliberately hardware-independent: handle_frame() is a pure function of
(current state, incoming frame) -> zero or more outgoing frames. Whatever
drives the actual RX/TX (see docs/EN/MONITOR_MODE.md) just needs to call it for
every received frame and inject_frame() each frame it returns, in order.

Scope, :
    1. Peer #1 broadcasts a Probe Request (SSID=STREETPASS_SSID) -- we reply
       with a unicast Probe Response carrying our own Nintendo tag.
    2. Peer #1 sends an Action frame (payload always observed as a fixed
       0x0000, project findings -- we reply in kind, 2026-09-17)
       plus a second, unicast Probe Request addressed to us (no SSID, BSSID
       = our MAC) -- we reply with a second Probe Response, at which point
       "the encrypted conversation" begins. That conversation's contents
       (SPTCP/SPMTP) are out of scope here; this module only gets the
       handshake to that point.
"""

from __future__ import annotations

import datetime
import os
import secrets
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Dict, List, Optional

from . import ccmp, crypto, dot11, spmtp, sptcp

LOCALLY_ADMINISTERED_BIT = 0x02

# 調査用の一時的なプロトコルトレース(STREETPASS_
# DEBUG_SPTCP=1で有効化)。恒久的なログ基盤ではなく、実機で会話がどこまで
# 進んでいるかを可視化するためだけのデバッグ出力。
_DEBUG_SPTCP = bool(os.environ.get("STREETPASS_DEBUG_SPTCP"))

_SPMTP_TYPE_NAMES = {
    0x41: "IDENTITY_CLIENT", 0x42: "IDENTITY_MASTER", 0x43: "IDENTITY_ACCEPT",
    0x11: "MODULE_FILTER_CLIENT", 0x12: "MODULE_FILTER_MASTER",
    0x21: "FRIEND_CODE_CLIENT", 0x22: "FRIEND_CODE_MASTER",
    0x23: "FRIEND_FLAG_CLIENT", 0x24: "FRIEND_FLAG_MASTER",
    0x31: "MESSAGE_BOX_METADATA_LIST_CLIENT", 0x32: "MESSAGE_BOX_METADATA_LIST_MASTER",
    0x33: "MESSAGE_BOX_METADATA_PARSED_CLIENT", 0x34: "MESSAGE_BOX_METADATA_PARSED_MASTER",
    0x81: "TMP_BOX_METADATA_LIST",
}


def _dbg(msg: str) -> None:
    if _DEBUG_SPTCP:
        print(f"[sptcp-debug] {msg}", flush=True)
MULTICAST_BIT = 0x01


@dataclass(frozen=True)
class SessionIdentity:
    """Our own StreetPass identity: the rotating continuous-scan consoleID +
    MAC (dot11.py), plus the separate "original" (real hardware) MAC,
    transferable ID, and session ID an SPMTP Identity packet (spmtp.py)
    discloses once the encrypted conversation starts -- confirmed live to be genuinely distinct from the continuous-scan
    MAC.
    """

    console_id: bytes
    mac: bytes
    original_mac: bytes = field(default_factory=lambda: secrets.token_bytes(6))
    transferable_id: bytes = field(default_factory=lambda: secrets.token_bytes(8))
    session_id: int = field(default_factory=lambda: secrets.randbits(32))


def generate_session_identity(
    transferable_id: Optional[bytes] = None,
    original_mac: Optional[bytes] = None,
    mac: Optional[bytes] = None,
    console_id: Optional[bytes] = None,
) -> SessionIdentity:
    """A fresh, locally-generated StreetPass identity.

    The real generation rule real consoles use is still unknown -- this just produces a random one with the right
    shape: a locally-administered, unicast MAC (matching the OUI bit pattern
    observed in the real capture) and a random 8-byte
    consoleID. original_mac/transferable_id/session_id are likewise just
    randomly generated (SessionIdentity's defaults) -- unlike the
    continuous-scan mac/console_id, project findings says session_id
    really is meant to be random per session, but original_mac on a real
    console is its fixed hardware MAC, not something regenerated each run.

    Pass transferable_id/original_mac explicitly to test docs/
    OPEN_QUESTIONS.md #1's leading hypothesis: that a real console cross-
    checks these against the outbound TMP Box's embedded Mii author_id/
    mii_id.deviceHash (mii_qr.MiiIdentity), and silently drops an outbound
    box whose "who is sending this" and "whose Mii is this" don't agree --
    every test so far that touched the Mii blob left this WiFi-layer
    identity randomly mismatched.

    mac/console_id let a caller also pin the continuous-scan-layer identity
    (802.11 source MAC + Nintendo Tag consoleID) to something derived from
    the Mii being sent, closing the one remaining gap `transferable_id`/
    `original_mac` alone don't cover (2026-09-15, project findings
    follow-up) -- project findings's real-hardware observation that this
    pair rotates on every successful hit suggests it's *not* meant to track
    the Mii's identity, but this has never been tested in isolation.
    """
    if mac is None:
        generated_mac = bytearray(secrets.token_bytes(6))
        generated_mac[0] = (generated_mac[0] | LOCALLY_ADMINISTERED_BIT) & ~MULTICAST_BIT
        mac = bytes(generated_mac)
    kwargs = {}
    if transferable_id is not None:
        kwargs["transferable_id"] = transferable_id
    if original_mac is not None:
        kwargs["original_mac"] = original_mac
    return SessionIdentity(
        console_id=console_id if console_id is not None else secrets.token_bytes(8),
        mac=mac,
        **kwargs,
    )


def _current_spmtp_timestamp() -> bytes:
    """Best-effort IdentityPacket.timestamp: year (u16 LE) + 2 zero bytes +
    month + day are confirmed against a real capture; the remaining 6 bytes' meaning is still unknown, zero-filled
    here."""
    now = datetime.datetime.now()
    return now.year.to_bytes(2, "little") + bytes(2) + bytes([now.month, now.day]) + bytes(6)


# project findings: SPTCP's max transfer window, confirmed live --
# matches 3dbrew's documented default buffer size (0x38b8, sent little-
# endian as 0xb838 in the header). One ACK (bytes_received, cumulative
# across the whole transfer -- ) is expected
# per this many bytes; it is *not* a position reset for bytes_sent, which
# keeps counting from the transfer's true start throughout.
TMP_BOX_WINDOW_SIZE = 0x38B8

# project findings: the largest single SPTCP packet a real capture
# ever carried -- matches this project's existing "fits in one Ethernet
# MTU so it's never fragmented" framing for the
# small, single-packet Info SPMTP messages; a segmented TMP Box download
# chunks into pieces this size too. Used for our own outbound sends so
# they're shaped the same way a real console's are.
TMP_BOX_PACKET_PAYLOAD_SIZE = 1452


def _is_spmtp_handshake_shaped(payload: bytes) -> bool:
    """Whether an SPTCP payload is an Info SPMTP handshake message (magic
    HANDSHAKE_MAGIC) as opposed to raw "Message Box SPMTP" TMP Box data
    (magic TMP_BOX_MAGIC, or a fragment of one with no magic of its own at
    all) -- project findings Both phases reuse the exact same SPTCP
    flags, so this is the only way to tell them apart."""
    try:
        spmtp.parse_handshake_header(payload)
        return True
    except ValueError:
        return False


class PeerState(Enum):
    DISCOVERED = "discovered"  # we've sent our first Probe Response
    ESTABLISHED = "established"  # second Probe Response sent, or the peer
    # has started sending us protected 802.11 Data frames (CCMP-encrypted
    # SPTCP traffic) -- see handle_frame()'s Data-frame branch below


@dataclass
class _PeerSession:
    """CCMP/SPTCP state for one peer, separate from the simple PeerState map
    so existing `responder.peers[mac] is PeerState.X` callers/tests are
    unaffected by it."""

    console_id: Optional[bytes] = None
    ccmp_key: Optional[bytes] = None
    tx_pn: int = 1  # every real capture so far starts a session at PN=1, not 0
    # An SPMTP reply payload waiting to go out once *our own* self-initiated
    # SPTCP handshake completes (project findings: a real peer expects
    # the sender of each SPMTP message, us included, to run a fresh 3-way
    # handshake immediately before that specific message, not just once for
    # the whole conversation) -- set when we send our handshake SYN, sent
    # and cleared once the peer's SYN+ACK arrives.
    pending_outgoing_payload: Optional[bytes] = None
    # Something to send *after* pending_outgoing_payload's own handshake
    # round finishes (i.e. once the peer bare-ACKs it) -- for a second
    # message queued up behind the first, since project findings's
    # one-handshake-per-message rule means they can't go out together.
    # project findings: used to send our own outbound TMP Box body.
    # Not necessarily sent right after our 0x81 reply is acknowledged --
    # see tmp_box_download_pending below.
    queued_send: Optional[bytes] = None
    # Whether the peer's own 0x81 (TMP Box Metadata List) declared a TMP
    # Box of its own that it hasn't finished sending us yet. docs/
    # PROTOCOL.md §7.36: a live capture showed initiating our own outbound
    # send (queued_send) *while the peer is also mid-transfer* leads it to
    # get stuck endlessly retransmitting its own first window -- real
    # hardware most likely doesn't expect (or handle) both sides trying to
    # push a TMP Box at once, matching 3dbrew's Conversation Flow text
    # describing strict turn-taking ("if B has more to send, B replies with
    # an ACK and initiates the handshake, then it's B's turn"). So
    # queued_send is only actually kicked off once this is False --
    # immediately if the peer's list was empty to begin with, or once their
    # download finishes (_handle_tmp_box_data clears this and fires
    # queued_send itself) if it wasn't.
    tmp_box_download_pending: bool = False
    # project findings: the full payload of an outbound send once it
    # no longer fits in a single packet (TMP_BOX_PACKET_PAYLOAD_SIZE) --
    # None whenever no such multi-window send is in progress. Set at the
    # same point pending_outgoing_payload used to be sent as one oversized
    # packet; outbound_send_pos (below) tracks how much of it the peer has
    # actually confirmed.
    outbound_send_payload: Optional[bytes] = None
    # How much of outbound_send_payload the peer has ACKed so far (docs/
    # PROTOCOL.md §7.38: cumulative, mirroring the receive side) -- also
    # where the next window's bytes_sent should start counting from.
    outbound_send_pos: int = 0
    # Set once (never cleared) the moment outbound_send_payload finishes
    # sending -- lets a driver loop (streetpass_loop.py) detect "our TMP
    # Box fully reached the peer" and end its cycle early instead of always
    # sleeping the full --cycle-seconds.
    outbound_send_done: bool = False
    # The peer's own Message Box Metadata List (0x31, project findings
    # §7.20) -- remembered so that when their "parsed" reply (0x33) arrives,
    # our own "parsed" reply (0x34) can declare interest in whichever of
    # *their* entries we actually want, rather than the two exchanges being
    # handled independently.
    peer_message_box_entries: List[spmtp.MessageBoxMetadataEntry] = field(default_factory=list)
    # Whether the peer's "parsed" response to *our* Message Box list (0x33,
    # project findings) named our outbound entry's title -- i.e.
    # whether they actually want the TMP Box we're offering, not just
    # whether we're offering one.
    peer_wants_our_tmp_box: bool = False
    # Raw bytes of a TMP Box (spmtp.py's TMP_BOX_MAGIC-prefixed content,
    # project findings) currently being downloaded from this peer,
    # reassembled from SPTCP's segmented transfer. Complete once it reaches
    # the size the leading TmpBoxHeader declares (parsed once enough bytes
    # have arrived) -- see StreetPassResponder.completed_tmp_boxes.
    tmp_box_buffer: bytearray = field(default_factory=bytearray, repr=False)
    # project findings: bytes_sent is cumulative across the *whole*
    # TMP Box transfer, not window-relative (§7.23's original assumption,
    # never actually exercised past window 1 until §7.38 got a real
    # transfer to advance beyond it) -- so it isn't a valid index into
    # tmp_box_buffer once a prior message has been extracted from the
    # front of it (del tmp_box_buffer[:size] shifts every later position
    # back by that much, but the peer's own bytes_sent keeps counting from
    # the whole queue's start). This offset is subtracted from bytes_sent
    # to get the correct local index; bumped by each extracted message's
    # size in _handle_tmp_box_data.
    tmp_box_stream_offset: int = 0
    #  (2026-09-15): this project's own progress
    # *initiating* contact with a peer, as opposed to PeerState above (which
    # only ever tracks answering a peer that probed *us*). None until we've
    # sent our own broadcast Probe Request to this specific peer_mac (i.e.
    # this peer was discovered by *their* broadcast reaching us first, and
    # we've decided to probe them back) -- see ProberStage.
    prober_stage: Optional[ProberStage] = None


class ProberStage(Enum):
    """This project's own state playing the "prober" side of the handshake
    ('s captured sequence, roles reversed):
    a real console spends time in *both* roles as it continuously scans, but
    this project had only ever implemented answering someone else's Probe
    Request (PeerState above) until 2026-09-15 -- 's "we've never sent an Action frame, or played prober at all" finding.
    """

    PROBED = "probed"  # we've sent our own broadcast Probe Request, waiting
    # for this peer's first (unicast) Probe Response.
    GOT_FIRST_RESPONSE = "got_first_response"  # ...and got it -- we've replied
    # with an Action frame + our own second (unicast) Probe Request, per the
    # captured sequence, and are now waiting for their second Probe Response.
    ESTABLISHED = "established"  # got their second Probe Response too -- the
    # 802.11-layer handshake is done, mirroring PeerState.ESTABLISHED (set
    # there too, so existing `peers[mac] is PeerState.ESTABLISHED` callers
    # don't need to know which role got us there). What happens next at the
    # SPTCP/SPMTP layer is deliberately left to the existing reactive
    # handling (_handle_data_frame() et al.) rather than this project also
    # trying to *initiate* that conversation -- every real capture on file
    # has the peer send the first CCMP Data frame unprompted once its own
    # Probe Response handshake (whichever side started it) completes, so
    # there's no confirmed need (or, without a live peer to test against,
    # confirmed *shape*) for this project to speak first at that layer too.


@dataclass
class StreetPassResponder:
    """Tracks per-peer handshake state and builds the frames to send back.

    keyslot_2e_key (keyslot 0x2E's AES normal key)
    is optional and defaults to None: without it, a peer's Data frames are
    still recognized (PeerState still reaches ESTABLISHED) but can't be
    decrypted or answered, same as before that key was known. Pass one from
    keyslot_2e.load_streetpass_normal_key() or oracle.py to enable the
    CCMP/SPTCP handshake reply below.

    friend_code is likewise optional: without one,
    Friend Code Client (0x21) gets an honest 0 back (§7.16), same as before.
    Pass friend_code.load_friend_code()'s result to disclose a real one
    instead -- use one you're fine with strangers being able to add anywhere
    in the world (not just a nearby StreetPass encounter), since unlike the
    rotating per-session MAC/consoleID a friend code doesn't expire.

    completed_tmp_boxes collects any TMP Box a peer actually transfers to us, keyed by peer MAC -- only populated once we
    start declaring interest in a peer's real Message Box entries (§7.20),
    which currently happens whenever one matches self.services. The bytes
    include the leading TmpBoxHeader; their content past that header (the
    actual "CECD savegame Message/Slot structures")
    isn't parsed anywhere in this codebase yet.

    outbound_message_box_entry/outbound_tmp_box
    are how this project's first-ever *outbound* Message/TMP Box content
    is offered -- both optional and both required together: without them,
    every peer gets the honest-empty-list behavior from before (§7.20).
    outbound_tmp_box's bytes are sent completely as-is (this project
    doesn't validate or interpret them) -- built from
    spmtp.build_tmp_box_header() plus whatever body you construct
    (recently_played.py's list, a greeting, or -- for testing what a real
    console actually requires, project findings's still-unsolved
    "opaque" leading region -- a real captured one, verbatim or perturbed).
    Only single-window (<= sptcp's ~0x38b8 byte transfer window) bodies are
    supported for now; nothing here chunks a larger one across multiple
    windows the way _handle_tmp_box_data() does for *receiving* one.
    """

    identity: SessionIdentity
    services: List[bytes]
    keyslot_2e_key: Optional[bytes] = None
    friend_code: Optional[int] = None
    hmac_key: bytes = crypto.HMAC_KEY_RETAIL_CANDIDATE
    outbound_message_box_entry: Optional[spmtp.MessageBoxMetadataEntry] = None
    outbound_tmp_box: Optional[bytes] = None
    peers: Dict[bytes, PeerState] = field(default_factory=dict)
    completed_tmp_boxes: Dict[bytes, List[bytes]] = field(default_factory=dict)
    _sessions: Dict[bytes, _PeerSession] = field(default_factory=dict, repr=False)
    _next_seq_num: int = field(default=0, repr=False)

    def handle_frame(self, dot11_frame: bytes) -> List[bytes]:
        """Given one received 802.11 frame (no radiotap header), return the
        raw frames to transmit back (possibly more than one -- see
        _handle_sptcp()'s per-message handshake) --
        or empty if this frame doesn't call for a response (or isn't a
        StreetPass frame we recognize)."""
        if len(dot11_frame) >= dot11.MGMT_HEADER_SIZE:
            header = dot11.parse_management_header(dot11_frame)
            if dot11.frame_type(header.frame_control) == dot11.FRAME_TYPE_DATA:
                return self._handle_data_frame(dot11_frame, header)

        try:
            action = dot11.parse_action_frame(dot11_frame)
        except ValueError:
            pass
        else:
            # project findings (2026-09-17): a peer acting as prober
            # sends us exactly one of these (payload always observed as a
            # fixed 0x0000 -- confirmed constant across 3 independent real
            # retries from console A live-captured this session, disproving the
            # "must echo/increment like a TCP ACK" hypothesis) right before
            # its second, unicast Probe Request. handle_frame() never had a
            # branch for this at all: it fell through to parse_probe_request(),
            # failed, and got silently dropped -- very likely why a peer that
            # probes *us* (this project had only ever been probed by a real
            # peer before, never replied to that peer's Action frame) kept
            # retrying its own handshake in an endless ~18s loop and never
            # reached a data exchange. Reply in kind with our own Action
            # frame (same fixed payload) so it can proceed.
            if action.header.addr1 != self.identity.mac:
                return []
            peer_mac = action.header.addr2
            return [dot11.build_action_frame(addr1=peer_mac, addr2=self.identity.mac, seq_ctrl=self._next_seq())]

        try:
            response = dot11.parse_probe_response(dot11_frame)
        except ValueError:
            pass
        else:
            # A reply to *our own* Probe Request (build_broadcast_probe()) --
            # the "prober" side of the handshake, project findings
            # #5/#6 (2026-09-15). This project had only ever answered a
            # peer's Probe Request before (the branches below); it's never
            # sent one itself, so receiving a Probe Response at all used to
            # be impossible.
            return self._handle_probe_response(response)

        try:
            probe = dot11.parse_probe_request(dot11_frame)
        except ValueError:
            return []  # neither a Probe Request nor a Probe Response

        if probe.ssid not in (dot11.STREETPASS_SSID.encode("ascii"), b""):
            return []

        peer_mac = probe.header.addr2
        is_broadcast = probe.header.addr1 == dot11.BROADCAST_MAC

        if is_broadcast:
            # The Nintendo tag is what identifies this as a StreetPass peer
            # (and carries the info -- services, consoleID -- needed to
            # answer it) rather than some unrelated device's broadcast probe.
            tag = dot11.find_nintendo_tag(probe.ies)
            if tag is None:
                return []
            # consoleID is needed later to build this peer's Hash Block
            # (crypto.build_hash_block()) once/if we get to CCMP -- captured
            # here since this broadcast Probe Request is the only frame that
            # carries it.
            self._session_for(peer_mac).console_id = tag.console_id
            # A real peer keeps re-broadcasting its continuous-scan Probe
            # Request even after the handshake has moved past this point
            # (confirmed live) -- downgrading an
            # already-ESTABLISHED peer back to DISCOVERED on one of those
            # would be a regression, not a resync, so only set it the first
            # time.
            if self.peers.get(peer_mac) is not PeerState.ESTABLISHED:
                self.peers[peer_mac] = PeerState.DISCOVERED
            return [self._build_response(dest=peer_mac)]

        # Unicast: the second Probe Request (project findings step 4),
        # addressed to us, from a peer we've already responded to once. A
        # real one carries no Nintendo tag at all -- just an empty SSID IE
        # plus Supported/Extended Supported Rates (confirmed live against a
        # real console A) -- so, unlike the broadcast
        # case above, this branch doesn't require finding one.
        if probe.header.addr1 != self.identity.mac:
            return []
        if self.peers.get(peer_mac) is not PeerState.DISCOVERED:
            return []

        self.peers[peer_mac] = PeerState.ESTABLISHED
        return [self._build_response(dest=peer_mac)]

    def _session_for(self, peer_mac: bytes) -> _PeerSession:
        return self._sessions.setdefault(peer_mac, _PeerSession())

    def build_broadcast_probe(self) -> bytes:
        """Our own broadcast Probe Request -- the "prober" side of
        continuous scanning (project findings step 1, roles reversed)
        that this project had never played before 2026-09-15 (docs/
        OPEN_QUESTIONS.md #5/#6: every test so far only ever answered a
        peer's own broadcast, never sent one ourselves or an Action frame).

        A real console keeps re-sending this continuously while scanning;
        callers (e.g. a periodic timer in whatever drives the actual radio
        -- see driver_bridge.py) are expected to call this repeatedly, the
        same way. Doesn't touch any per-peer state itself -- broadcasting
        doesn't know in advance who (if anyone) will answer.
        _handle_probe_response() lazily starts tracking ProberStage for
        whichever peer actually replies.
        """
        nintendo_tag = dot11.build_nintendo_tag(self.services, self.identity.console_id)
        vendor_ie_body = dot11.NINTENDO_OUI + bytes([dot11.NINTENDO_OUI_TYPE]) + nintendo_tag
        ies = [
            (dot11.SUPPORTED_RATES_IE_TAG, dot11.CAPTURED_SUPPORTED_RATES),
            (dot11.EXTENDED_SUPPORTED_RATES_IE_TAG, dot11.CAPTURED_EXTENDED_SUPPORTED_RATES),
            (dot11.VENDOR_SPECIFIC_IE_TAG, vendor_ie_body),
        ]
        return dot11.build_probe_request(addr2=self.identity.mac, ies=ies, seq_ctrl=self._next_seq())

    def _handle_probe_response(self, response: dot11.ProbeResponse) -> List[bytes]:
        """A reply to our own build_broadcast_probe() (or our own second,
        unicast Probe Request below) -- the prober side of the handshake,
        mirrored from the captured real sequence where *we* were the one
        being probed:

            1. our broadcast Probe Request -> peer's first Probe Response
            2. our Action frame + our second (unicast) Probe Request
            3. peer's second Probe Response -> 802.11 handshake done

        Deliberately doesn't try to initiate the SPTCP/SPMTP conversation
        once step 3 completes -- see ProberStage.ESTABLISHED's docstring.
        """
        if response.header.addr1 != self.identity.mac:
            return []
        peer_mac = response.header.addr2
        session = self._session_for(peer_mac)

        if session.prober_stage in (None, ProberStage.PROBED):
            # Either their first reply to a broadcast we sent (prober_stage
            # is still None -- we don't track anything until someone
            # actually answers), or a duplicate of that same first reply
            # arriving again (still PROBED, e.g. our Action frame or second
            # Probe Request got lost and they retried). Either way: answer
            # with an Action frame + our own second (unicast) Probe Request.
            #
            #  wild-capture bug (2026-09-16):
            # an ordinary WiFi AP unicasting a mundane Probe Response back
            # to our broadcast (routers commonly do this regardless of
            # SSID match, and it's addr1-matched to us since we asked)
            # used to sail straight through this branch with no tag check
            # at all, advancing prober_stage on pure noise -- a single
            # retransmitted duplicate of that same non-3DS frame was then
            # enough to satisfy the *second* branch below too, producing a
            # bogus ESTABLISHED peer that never sent a byte of real
            # StreetPass traffic. Require an actual Nintendo tag before
            # treating anything as a reply to our own probe.
            tag = dot11.find_nintendo_tag(response.ies)
            if tag is None:
                return []
            # Mirrors how a broadcast Probe Request's Nintendo tag is
            # captured in the responder role above -- needed later for
            # this peer's Hash Block (crypto.build_hash_block()).
            session.console_id = tag.console_id
            session.prober_stage = ProberStage.GOT_FIRST_RESPONSE
            action = dot11.build_action_frame(addr1=peer_mac, addr2=self.identity.mac, seq_ctrl=self._next_seq())
            second_probe = dot11.build_probe_request(
                addr2=self.identity.mac, addr1=peer_mac, ssid=b"", ies=None, seq_ctrl=self._next_seq(),
            )
            return [action, second_probe]

        if session.prober_stage == ProberStage.GOT_FIRST_RESPONSE:
            # Their second Probe Response -- the 802.11-layer handshake is
            # done. Mirrors PeerState.ESTABLISHED (a real peer starts
            # sending its own CCMP Data frames unprompted immediately after
            # this point in every capture on file, regardless of which side
            # was prober) so the existing _handle_data_frame() picks the
            # conversation up from here with zero further changes needed.
            session.prober_stage = ProberStage.ESTABLISHED
            if self.peers.get(peer_mac) is not PeerState.ESTABLISHED:
                self.peers[peer_mac] = PeerState.ESTABLISHED
            return []

        return []  # already ESTABLISHED -- a stray/duplicate response

    def outbound_send_completed(self) -> bool:
        """Whether our outbound_tmp_box has fully reached any peer this
        session -- lets a driver loop (streetpass_loop.py) end its cycle
        early instead of always sleeping the full --cycle-seconds."""
        return any(s.outbound_send_done for s in self._sessions.values())

    def _handle_data_frame(self, dot11_frame: bytes, header: dot11.ManagementFrameHeader) -> List[bytes]:
        """A protected 802.11 Data frame addressed to us from a known peer
        is the CCMP-encrypted SPTCP conversation (sptcp.py) starting --
        confirmed live against a real console,
        where receiving one is proof the peer accepted our identity even
        without us ever seeing a second unicast Probe Request.

        Marks the sender ESTABLISHED either way. Actually decrypting and
        replying additionally needs keyslot_2e_key and this peer's
        consoleID (captured from its broadcast Probe Request) -- without
        either, this only updates state, same as before keyslot 0x2E's key
        was known.
        """
        if not dot11.is_protected(header.frame_control):
            return []
        if header.addr1 != self.identity.mac:
            return []
        peer_mac = header.addr2
        if self.peers.get(peer_mac) not in (PeerState.DISCOVERED, PeerState.ESTABLISHED):
            return []
        self.peers[peer_mac] = PeerState.ESTABLISHED

        session = self._sessions.get(peer_mac)
        if self.keyslot_2e_key is None or session is None or session.console_id is None:
            return []

        if session.ccmp_key is None:
            hash_block = crypto.build_hash_block(
                host_console_id=self.identity.console_id,
                client_console_id=session.console_id,
                host_mac=self.identity.mac,
                client_mac=peer_mac,
            )
            session.ccmp_key = crypto.derive_ccmp_key(hash_block, self.hmac_key, self.keyslot_2e_key)

        try:
            decrypted = ccmp.decrypt_data_frame(dot11_frame, session.ccmp_key)
        except ccmp.CcmpError as e:
            _dbg(f"CCMP decrypt FAILED from {peer_mac.hex()}: {e}")
            return []  # wrong key (e.g. consoleID/MAC rotated) or a frame we can't make sense of

        return self._handle_sptcp(decrypted.plaintext, peer_mac, session)

    def _handle_sptcp(self, plaintext: bytes, peer_mac: bytes, session: _PeerSession) -> List[bytes]:
        """Answer an SPTCP packet. project findings (re-reading the
        primary source closely, after §7.9-7.11's combined-ACK+data attempt
        didn't work): a fresh 3-way handshake has to precede *every single*
        SPMTP message, initiated by whichever side is about to send that
        particular message -- not just once for the whole conversation.
        So:
          - a bare SYN is the peer wanting to send us something -> SYN+ACK, same as before;
          - a bare SYN+ACK is the peer answering *our* handshake SYN (see
            the PSH+ACK+END case below) -> our final ACK, then immediately
            our actual queued reply payload as its own packet;
          - a complete (PSH+ACK+END, i.e. not fragmented across multiple
            packets) SPMTP-carrying packet gets an ACK whose bytes_received
            reflects what we actually received (§7.12 -- previously always
            0, which was also wrong), and if we have a reply
            (_handle_spmtp()), we *initiate our own handshake* (send a SYN)
            and queue the reply rather than sending it directly.
        Anything else (e.g. the handshake's final bare ACK when we're not
        the one who just sent something) is left unanswered.
        """
        preamble, body = plaintext[:len(sptcp.MSDU_PREAMBLE)], plaintext[len(sptcp.MSDU_PREAMBLE):]
        if preamble != sptcp.MSDU_PREAMBLE:
            _dbg(f"bad MSDU preamble from {peer_mac.hex()}: {preamble.hex()}")
            return []
        try:
            header, payload = sptcp.parse_packet(body)
        except ValueError as e:
            _dbg(f"sptcp.parse_packet FAILED from {peer_mac.hex()}: {e}")
            return []

        _dbg(f"RX sptcp flags={header.flags:#04x} bytes_sent={header.bytes_sent} "
             f"bytes_received={header.bytes_received} payload_len={len(payload)} "
             f"handshake_shaped={_is_spmtp_handshake_shaped(payload) if payload else 'n/a'}")

        if payload and not _is_spmtp_handshake_shaped(payload):
            # "Message Box SPMTP": a segmented TMP
            # Box download, not an Info SPMTP handshake message -- distinct
            # from the PSH+ACK+END case below only by *content* (its magic
            # is spmtp.TMP_BOX_MAGIC, not HANDSHAKE_MAGIC), since both
            # phases reuse the exact same SPTCP flags.
            return self._handle_tmp_box_data(header, payload, peer_mac, session)

        if header.flags == sptcp.FLAG_SYN:
            reply_body = sptcp.build_handshake_packet(sptcp.FLAG_SYN | sptcp.FLAG_ACK)
            return [self._send_sptcp(peer_mac, session, reply_body)]

        if header.flags == (sptcp.FLAG_SYN | sptcp.FLAG_ACK):
            if session.pending_outgoing_payload is None:
                return []  # not something we were waiting for
            payload_to_send, session.pending_outgoing_payload = session.pending_outgoing_payload, None
            ack_frame = self._send_sptcp(peer_mac, session, sptcp.build_handshake_packet(sptcp.FLAG_ACK))
            # project findings: anything over one packet's worth needs
            # the same windowed shape a real console's own sends use (every
            # Info SPMTP message fits in one packet already, so this is a
            # no-op split for those -- only our own outbound TMP Box sends
            # are actually large enough to matter).
            session.outbound_send_payload = payload_to_send
            session.outbound_send_pos = 0
            return [ack_frame, *self._send_tmp_box_window(peer_mac, session)]

        if header.flags == sptcp.FLAG_ACK and session.outbound_send_payload is not None:
            # project findings: the peer ACKing one of our own send's
            # windows (mirrors how _handle_tmp_box_data() ACKs the peer's
            # windows to us) -- bytes_received is its cumulative progress
            # so far; trust it as where the next window should continue
            # from, then send that window, or stop once nothing's left.
            session.outbound_send_pos = header.bytes_received
            _dbg(f"our TMP Box send progress: {session.outbound_send_pos}/{len(session.outbound_send_payload)} bytes")
            if session.outbound_send_pos < len(session.outbound_send_payload):
                return self._send_tmp_box_window(peer_mac, session)
            _dbg("our TMP Box send COMPLETE")
            session.outbound_send_payload = None
            session.outbound_send_pos = 0
            session.outbound_send_done = True
            # No return here: this same bare ACK closing out our send is
            # exactly the trigger the queued_send branch below is waiting
            # for, so let it fall through to that
            # check instead of ending the round here unconditionally.

        if header.flags == (sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END):
            ack_body = sptcp.build_packet(sptcp.FLAG_ACK, bytes_received=len(payload))
            frames = [self._send_sptcp(peer_mac, session, ack_body)]
            reply_payload = self._handle_spmtp(payload, session)
            if reply_payload is not None:
                session.pending_outgoing_payload = reply_payload
                frames.append(self._send_sptcp(peer_mac, session, sptcp.build_handshake_packet(sptcp.FLAG_SYN)))
            return frames

        if header.flags in ((sptcp.FLAG_ACK | sptcp.FLAG_FIN), sptcp.FLAG_FIN):
            # : once neither side has any more
            # info messages to send, the peer closes the conversation with a
            # FIN -- 3dbrew's Conversation Flow text describes it combined
            # with ACK, and that's what we implemented first, but a live
            # capture (§7.21) showed a real peer send a *bare* FIN (no ACK
            # bit) instead, right after actually reaching the TMP Box stage.
            # We answer either shape in kind with ACK+FIN (no handshake
            # needed); the peer's final bare ACK after that falls through to
            # the case below, which is already correct: nothing more to send.
            reply_body = sptcp.build_handshake_packet(sptcp.FLAG_ACK | sptcp.FLAG_FIN)
            return [self._send_sptcp(peer_mac, session, reply_body)]

        if header.flags == sptcp.FLAG_ACK and session.queued_send is not None and not session.tmp_box_download_pending:
            # project findings: this bare ACK completes the handshake
            # round for whatever we just sent (project findings: one
            # handshake per message) -- time to start the *next* one we had
            # queued up behind it (our outbound TMP Box, right now the only
            # thing that ever gets queued this way). Only once the peer
            # isn't mid-transfer itself, though --
            # if tmp_box_download_pending is still True, _handle_tmp_box_data()
            # fires this same queued_send once their download finishes instead.
            session.pending_outgoing_payload, session.queued_send = session.queued_send, None
            return [self._send_sptcp(peer_mac, session, sptcp.build_handshake_packet(sptcp.FLAG_SYN))]

        return []  # e.g. the handshake's final bare ACK -- nothing to send back

    def _send_tmp_box_window(self, peer_mac: bytes, session: "_PeerSession") -> List[bytes]:
        """Send one window's worth (project findings's TMP_BOX_WINDOW_SIZE)
        of session.outbound_send_payload, starting at session.outbound_send_pos,
        as a burst of TMP_BOX_PACKET_PAYLOAD_SIZE-sized packets -- mirroring
        the shape a real console's own sends arrive in: every packet but the window's last is a bare ACK carrying
        data, bytes_sent is the cumulative offset from the *whole transfer's*
        start (not window-relative), and only the last packet of the window
        is flagged PSH+ACK+END. The peer's own ACK for that last packet
        (handled in _handle_sptcp()'s outbound_send_payload branch) is what
        triggers the next window, or ends the send once nothing's left.
        """
        payload = session.outbound_send_payload
        assert payload is not None
        start = session.outbound_send_pos
        window_end = min(start + TMP_BOX_WINDOW_SIZE, len(payload))
        frames: List[bytes] = []
        pos = start
        while pos < window_end:
            chunk_end = min(pos + TMP_BOX_PACKET_PAYLOAD_SIZE, window_end)
            chunk = payload[pos:chunk_end]
            is_last = chunk_end == window_end
            flags = (sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END) if is_last else sptcp.FLAG_ACK
            frames.append(self._send_sptcp(peer_mac, session, sptcp.build_packet(flags, chunk, bytes_sent=pos)))
            pos = chunk_end
        return frames

    def _handle_tmp_box_data(
        self, header: sptcp.SptcpHeader, payload: bytes, peer_mac: bytes, session: _PeerSession
    ) -> List[bytes]:
        """Accumulate one chunk of a segmented TMP Box download (docs/
        PROTOCOL.md §7.23, first observed live after §7.22's send_state fix
        got a real peer to actually start one).

        project findings: bytes_sent is a cumulative offset across
        the *whole* transfer, confirmed live once a real transfer finally
        advanced past its first window (§7.38's ack fix) -- §7.23's
        original "offset within the current window" reading had only ever
        been exercised *within* one window before, since no capture had
        gotten past window 1 until then. "Windows" are just a flow-control
        checkpoint (an ACK once every TMP_BOX_WINDOW_SIZE bytes, per
        project findings's "ACK the bytes received once PSH+END"),
        not a position reset -- only a genuine from-scratch restart of the
        transfer (RF loss, confirmed live in §7.34) resets bytes_sent to 0.

        session.tmp_box_stream_offset (see its docstring) turns bytes_sent
        into `pos`, an index local to tmp_box_buffer. A packet whose `pos`
        lands exactly at the buffer's current end is a normal continuation
        -- appended. One at an *earlier* `pos` whose content matches what's
        already buffered there is a harmless retransmission of data we
        already have (§7.34, and its RF-dropped-leading-packet variant,
        §7.35) -- ACKed below but not re-appended, so it can't corrupt
        what follows. Anything else means the peer is restarting the
        transfer from that position -- rewind the buffer to there and
        accept it fresh.

        Only the window's last packet (PSH+ACK+END) gets an ACK back;
        every packet before that is silently buffered -- confirmed live.
        """
        buf = session.tmp_box_buffer
        if payload:
            pos = header.bytes_sent - session.tmp_box_stream_offset
            if pos == len(buf):
                buf += payload
            elif 0 <= pos and pos + len(payload) <= len(buf) and bytes(buf[pos:pos + len(payload)]) == payload:
                pass  # retransmission of data we already have -- nothing to do
            elif pos >= 0:
                del buf[pos:]
                buf += payload
            # else: pos < 0 -- stale data preceding a message we've already
            # extracted (see tmp_box_stream_offset) -- ignore entirely.

        frames: List[bytes] = []
        if header.flags == (sptcp.FLAG_PSH | sptcp.FLAG_ACK | sptcp.FLAG_END):
            # project findings: 3dbrew's own text (already quoted in
            # §7.12) says this ACK must carry "the number of payload bytes
            # received from the current SPMTP *until that point*" -- a
            # cumulative count symmetric with bytes_sent, not just this one
            # packet's own length. Every case that "confirmed" the old
            # len(payload)-only behavior was a single-packet message, where
            # the two are numerically identical, so the distinction was
            # never actually exercised until a real multi-packet window
            # did -- and a real peer stuck endlessly retransmitting window
            # 1 (see §7.36/§7.37) is exactly what you'd expect if it read
            # our too-small bytes_received as "you only got a fraction of
            # what I sent, here's the whole window again."
            ack_body = sptcp.build_packet(sptcp.FLAG_ACK, bytes_received=header.bytes_sent + len(payload))
            frames.append(self._send_sptcp(peer_mac, session, ack_body))

        if len(buf) >= spmtp.TMP_BOX_HEADER_SIZE:
            try:
                tmp_box_header = spmtp.parse_tmp_box_header(bytes(buf[:spmtp.TMP_BOX_HEADER_SIZE]))
            except ValueError:
                tmp_box_header = None
            if tmp_box_header is not None and len(buf) >= tmp_box_header.size:
                complete = bytes(buf[:tmp_box_header.size])
                del buf[:tmp_box_header.size]
                session.tmp_box_stream_offset += tmp_box_header.size
                self.completed_tmp_boxes.setdefault(peer_mac, []).append(complete)

                # project findings: the peer's download (which we were
                # deferring our own send behind, see _handle_sptcp()'s bare-
                # ACK branch and _handle_spmtp()'s TMP_BOX_METADATA_LIST
                # branch) just finished -- it's our turn now, if we had one
                # queued.
                session.tmp_box_download_pending = False
                if session.queued_send is not None:
                    session.pending_outgoing_payload, session.queued_send = session.queued_send, None
                    frames.append(self._send_sptcp(peer_mac, session, sptcp.build_handshake_packet(sptcp.FLAG_SYN)))

        return frames

    def _handle_spmtp(self, payload: bytes, session: _PeerSession) -> Optional[bytes]:
        """Given one SPTCP packet's SPMTP payload, return our reply payload
        (or None to just bare-ACK it at the SPTCP level). Confirmed live that answering Identity Client (0x41) with
        our own Identity (0x42), and the peer's own Identity Accept (0x43)
        with our own 0x43, both get accepted -- the peer went on to send
        Module Filter Client (0x11) next, matching the fixed message order
        (project findings: 0x41, 0x42, 0x43, 0x43, 0x11, 0x12, ...).
        Module Filter's content turned out to be exactly a Nintendo tag
        (dot11.py's build_nintendo_tag()/parse_nintendo_tag() -- same
        services+consoleID structure as the 802.11 Probe Request IE, just
        resent inside the encrypted SPMTP layer), confirmed live: a real
        Module Filter Client payload parsed with zero errors and its
        consoleID matched the peer's Probe Request consoleID exactly. That exchange (0x11/0x12) was then
        confirmed live too, immediately followed by the peer's real Friend
        Code (0x21) -- we answer with self.friend_code
        if one's configured (a real, checksum-valid code -- see
        StreetPassResponder's docstring), otherwise an honest 0, and Friend
        Flag (0x23) with 0 ("not a friend"), which is simply true for a
        stranger encounter, not a placeholder.
        Message Box Metadata List (0x31) always gets an empty list back
        (0x32) -- this project has no real StreetPass game data of its own
        to advertise. But a live capture showed the
        peer's own 0x31 list is *not* empty -- a real queued Mii Plaza
        message -- so our "parsed" reply (0x34, answering their *original*
        0x31 list, not their 0x33) now expresses interest in whichever of
        their entries match a service we declared support for, rather than unconditionally empty. TMP Box
        Metadata (0x81) itself is still always an empty list back -- this
        project can't build a real TMP Box to send, and downloading a
        requested one isn't implemented yet either, so nothing further
        happens once a title's been marked wanted here. That's the last
        message in the fixed order; _handle_sptcp()
        closes the conversation gracefully from there once both sides are
        empty."""
        try:
            header = spmtp.parse_handshake_header(payload)
        except ValueError as e:
            _dbg(f"spmtp.parse_handshake_header FAILED: {e}")
            return None

        _dbg(f"SPMTP RX type={_SPMTP_TYPE_NAMES.get(header.packet_type, hex(header.packet_type))}")

        if header.packet_type == spmtp.PacketType.IDENTITY_CLIENT:
            identity_packet = spmtp.IdentityPacket(
                transferable_id=self.identity.transferable_id,
                session_id=self.identity.session_id,
                original_mac=self.identity.original_mac,
                timestamp=_current_spmtp_timestamp(),
            )
            reply_header = spmtp.HandshakeHeader(
                packet_type=spmtp.PacketType.IDENTITY_MASTER,
                content_size=spmtp.IdentityPacket.SIZE,
            )
            return spmtp.build_handshake_header(reply_header) + spmtp.build_identity_packet(identity_packet)

        if header.packet_type == spmtp.PacketType.IDENTITY_ACCEPT:
            reply_header = spmtp.HandshakeHeader(
                packet_type=spmtp.PacketType.IDENTITY_ACCEPT,
                content_size=spmtp.IDENTITY_ACCEPT_SIZE,
            )
            return spmtp.build_handshake_header(reply_header) + spmtp.build_identity_accept_packet()

        if header.packet_type == spmtp.PacketType.MODULE_FILTER_CLIENT:
            nintendo_tag = dot11.build_nintendo_tag(self.services, self.identity.console_id)
            reply_header = spmtp.HandshakeHeader(
                packet_type=spmtp.PacketType.MODULE_FILTER_MASTER,
                content_size=len(nintendo_tag),
            )
            return spmtp.build_handshake_header(reply_header) + nintendo_tag

        if header.packet_type == spmtp.PacketType.FRIEND_CODE_CLIENT:
            # self.friend_code is a real, checksum-valid friend code
            # when configured; 0 (not a fabricated
            # value) otherwise, same as before (§7.16).
            friend_code_packet = spmtp.FriendCodePacket(friend_code=self.friend_code or 0)
            reply_header = spmtp.HandshakeHeader(packet_type=spmtp.PacketType.FRIEND_CODE_MASTER, content_size=8)
            return spmtp.build_handshake_header(reply_header) + spmtp.build_friend_code_packet(friend_code_packet)

        if header.packet_type == spmtp.PacketType.FRIEND_FLAG_CLIENT:
            # We've never seen this peer before, so "not a friend" (0) is
            # simply true, not a placeholder.
            friend_flag_packet = spmtp.FriendFlagPacket(flag=0)
            reply_header = spmtp.HandshakeHeader(packet_type=spmtp.PacketType.FRIEND_FLAG_MASTER, content_size=4)
            return spmtp.build_handshake_header(reply_header) + spmtp.build_friend_flag_packet(friend_flag_packet)

        if header.packet_type == spmtp.PacketType.MESSAGE_BOX_METADATA_LIST_CLIENT:
            # Without outbound_message_box_entry configured, we have no
            # real StreetPass game data of our own to advertise (docs/
            # PROTOCOL.md §7.5's TMP Box message content isn't parsed or
            # fabricated anywhere in this codebase) -- an empty list is the
            # honest answer, same reasoning as Friend Code/Flag. With one
            # configured (project findings, this project's first
            # outbound Message Box content), we offer exactly that single
            # entry instead. Their entries are remembered (not necessarily
            # empty -- ) so the 0x34 reply below
            # can react to them once their 0x33 arrives.
            session.peer_message_box_entries = spmtp.parse_message_box_metadata_list(
                payload[spmtp.HANDSHAKE_HEADER_SIZE:]
            )
            our_entries = [self.outbound_message_box_entry] if self.outbound_message_box_entry is not None else []
            our_list = spmtp.build_message_box_metadata_list(our_entries)
            reply_header = spmtp.HandshakeHeader(
                packet_type=spmtp.PacketType.MESSAGE_BOX_METADATA_LIST_MASTER, content_size=len(our_list),
            )
            return spmtp.build_handshake_header(reply_header) + our_list

        if header.packet_type == spmtp.PacketType.MESSAGE_BOX_METADATA_PARSED_CLIENT:
            # This is the peer's "parsed" response to *our* 0x32 -- when
            # that was empty (no outbound_message_box_entry configured),
            # there was nothing in it to react to. With one configured
            #, this tells us whether the peer
            # actually wants what we're offering, not just that we're
            # offering it -- checked by title, matching how we check *our*
            # interest in *their* entries below.
            if self.outbound_message_box_entry is not None:
                peer_response_entries = spmtp.parse_message_box_metadata_list(payload[spmtp.HANDSHAKE_HEADER_SIZE:])
                session.peer_wants_our_tmp_box = any(
                    e.title_id == self.outbound_message_box_entry.title_id for e in peer_response_entries
                )
                _dbg(f"peer's 0x33 parsed-response entries={peer_response_entries} "
                     f"-> peer_wants_our_tmp_box={session.peer_wants_our_tmp_box}")

            # What matters for *our* reply here is *our* "parsed" response
            # to *their* original 0x31 list (session.peer_message_box_entries,
            # captured above). We declare interest in whichever of those
            # match a service we actually support.
            #
            # project findings's field table calls send_state "field
            # modified by peer when sent back in packets 0x33/0x34" -- live
            # testing an unmodified echo (§7.20/§7.21) got the entry
            # transport-accepted (ACKed with a matching byte count) but
            # never triggered an actual TMP Box transfer, twice reproduced;
            # since that field is specifically documented as something we're
            # expected to *change*, not just relay, this sets it to 1
            # as a best-effort "requested" sentinel
            # -- still unconfirmed, but a better-motivated guess than an
            # untouched echo.
            wanted_title_ids = self._wanted_title_ids()
            wanted_entries = [
                replace(e, send_state=1)
                for e in session.peer_message_box_entries
                if e.title_id in wanted_title_ids
            ]
            wanted_list = spmtp.build_message_box_metadata_list(wanted_entries)
            reply_header = spmtp.HandshakeHeader(
                packet_type=spmtp.PacketType.MESSAGE_BOX_METADATA_PARSED_MASTER, content_size=len(wanted_list),
            )
            return spmtp.build_handshake_header(reply_header) + wanted_list

        if header.packet_type == spmtp.PacketType.TMP_BOX_METADATA_LIST:
            # Sent by both sides using the same packet type (project findings
            # §7.3's fixed order lists 0x81 twice). Without an outbound TMP
            # Box the peer actually wants, an empty
            # list closes out the fixed message order same as before --
            # project findings: with both sides empty, the peer
            # follows up by ACK+FIN-ing our reply to gracefully end the
            # conversation (handled in _handle_sptcp(), not here). With one,
            # we advertise it here and queue actually sending its bytes
            # (session.queued_send, picked up in _handle_sptcp() once this
            # reply itself is acknowledged -- project findings's one-
            # handshake-per-message rule means it can't go out together with
            # this reply).
            #
            # project findings: if the PEER's own list here is non-
            # empty, it's about to start sending US its TMP Box -- hold off
            # firing our own queued_send (see the FLAG_ACK branch in
            # _handle_sptcp()) until that download finishes, since a live
            # capture showed initiating both sides' handshakes at once
            # leaves real hardware stuck endlessly retransmitting its own
            # first window.
            peer_tmp_box_entries = spmtp.parse_tmp_box_metadata_list(payload[spmtp.HANDSHAKE_HEADER_SIZE:])
            session.tmp_box_download_pending = bool(peer_tmp_box_entries)
            our_entries: List[spmtp.TmpBoxMetadataEntry] = []
            if (
                self.outbound_message_box_entry is not None
                and self.outbound_tmp_box is not None
                and session.peer_wants_our_tmp_box
            ):
                our_entries = [spmtp.TmpBoxMetadataEntry(
                    title_id=self.outbound_message_box_entry.title_id, size=len(self.outbound_tmp_box),
                )]
                session.queued_send = self.outbound_tmp_box
            _dbg(f"0x81 TMP_BOX_METADATA_LIST: peer_entries={peer_tmp_box_entries} "
                 f"peer_wants_our_tmp_box={session.peer_wants_our_tmp_box} "
                 f"-> our_entries={our_entries} queued_send={'set' if session.queued_send else None}")
            our_list = spmtp.build_tmp_box_metadata_list(our_entries)
            reply_header = spmtp.HandshakeHeader(
                packet_type=spmtp.PacketType.TMP_BOX_METADATA_LIST, content_size=len(our_list),
            )
            return spmtp.build_handshake_header(reply_header) + our_list

        return None

    def peer_message_boxes(self) -> Dict[bytes, List[spmtp.MessageBoxMetadataEntry]]:
        """The message boxes (title ID, send mode, size, count, ...) each peer announced in its Message Box Metadata
        List: which games the console has StreetPass data queued for. Filled during the handshake."""
        return {mac: list(sess.peer_message_box_entries) for mac, sess in self._sessions.items()
                if sess.peer_message_box_entries}

    def _wanted_title_ids(self) -> set:
        """The title IDs (MessageBoxMetadataEntry.title_id) implied by self.services: a StreetPass "service" tag
        (dot11.py's SERVICE_ENTRY_SIZE=5 bytes) is that title ID's low 4
        bytes read big-endian, plus one more byte we don't use here --
        confirmed live: MII_PLAZA_SERVICE = bytes.fromhex("0002080000") and
        a real peer's queued Mii Plaza message both point at title_id
        0x00020800."""
        return {int.from_bytes(service[:4], "big") for service in self.services}

    def _send_sptcp(self, peer_mac: bytes, session: _PeerSession, body: bytes) -> bytes:
        pn, session.tx_pn = session.tx_pn, session.tx_pn + 1
        return ccmp.build_data_frame(
            dest=peer_mac,
            src=self.identity.mac,
            bssid=self.identity.mac,
            seq_ctrl=self._next_seq(),
            pn=pn,
            key=session.ccmp_key,
            plaintext=sptcp.MSDU_PREAMBLE + body,
        )

    def _build_response(self, dest: bytes) -> bytes:
        nintendo_tag = dot11.build_nintendo_tag(self.services, self.identity.console_id)
        vendor_ie_body = dot11.NINTENDO_OUI + bytes([dot11.NINTENDO_OUI_TYPE]) + nintendo_tag
        ies = [
            (dot11.SSID_IE_TAG, dot11.STREETPASS_SSID.encode("ascii")),
            (dot11.SUPPORTED_RATES_IE_TAG, dot11.CAPTURED_SUPPORTED_RATES),
            (dot11.EXTENDED_SUPPORTED_RATES_IE_TAG, dot11.CAPTURED_EXTENDED_SUPPORTED_RATES),
            (dot11.VENDOR_SPECIFIC_IE_TAG, vendor_ie_body),
        ]
        header = dot11.ManagementFrameHeader(
            frame_control=dot11.FC_PROBE_REQUEST,  # placeholder; build_probe_response fixes this
            duration=0,
            addr1=dest,
            addr2=self.identity.mac,
            addr3=self.identity.mac,
            seq_ctrl=self._next_seq(),
        )
        return dot11.build_probe_response(header=header, ies=ies)

    def _next_seq(self) -> int:
        """A fresh 802.11 sequence number (fragment 0) for each frame we
        transmit. A real 3DS in continuous-scan mode re-sends its own Probe
        Request every ~0.2-0.3s (project findings, confirmed live in
        §7.6); every one of our replies carrying the *same* seq_ctrl looked
        like a retransmission to the peer's own 802.11 duplicate-detection,
        which is suspected of silently dropping every reply after the first
        (§7.6) -- this is what fixes that."""
        seq = self._next_seq_num
        self._next_seq_num = (self._next_seq_num + 1) & 0xFFF
        return seq << 4
