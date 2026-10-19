// project findings, candidate 4 (2026-09-15): the community
// homebrew "NetPass" (gitlab.com/3ds-netpass/netpass) delivers StreetPass
// hits over the internet via cecd:s's SPR (SpotPass Relay, the same IPC
// the official now-defunct StreetPass Relay stations used) instead of the
// 802.11 WiFi layer, and it demonstrably works with 100%-genuine,
// unmodified box content. This project has already proven the opposite
// case: 100%-genuine, unmodified real Mii data (extracted from another
// console's meet.dat) still gets silently rejected when sent over WiFi.
//
// This probe reproduces the SPR "receive" half entirely locally (no
// network, no peer console) by calling the raw cecd:s IPC commands
// directly, feeding it one of our own already-proven-to-fail-over-WiFi
// TMP Box bodies. If Mii Plaza shows it as a new visitor after this, the
// root cause is confirmed to be somewhere in this project's WiFi-layer
// implementation specifically (not CECD's storage, not the Mii content).
// If it's still rejected, the cause survives even a completely different
// delivery transport and must be in the message content/CECD-side
// bookkeeping itself.
//
// Raw IPC command headers, the CecSlotHeader/SlotMetadata layouts, and
// the "0xFF flags" constant in SprAddSlot were not documented on 3dbrew
// (only the command header values were) -- they come from the actual
// working implementation the NetPass devs published:
// github.com/allfor0/netpass source/cecd.c (GPLv3), read 2026-09-15 as
// part of re-searching prior art for this exact question.
#include <3ds.h>
#include <3ds/ipc.h>
#include <3ds/srv.h>
#include <3ds/svc.h>
#include <3ds/synchronization.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define MII_PLAZA_TITLE_ID 0x00020800u
#define CEC_COMMAND_OVER_BOSS 0x12u
#define CEC_STATE_ABBREV_INACTIVE 2u

typedef struct {
    int send_method;
    u32 title_id;
    u32 size;
} SlotMetadata;

typedef struct {
    u16 magic;   // 0x6161 'aa'
    u16 padding;
    u32 size;    // sizeof(CecSlotHeader) + inner message size
    u32 title_id;
    u32 batch_id;
    u32 message_count;
} CecSlotHeader;

static Handle g_cecdHandle;
static FILE *g_log;

static void writelog(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(g_log, fmt, args);
    va_end(args);
    fflush(g_log);
}

static const char *rs(Result res) {
    static char buf[16][20];
    static int i = 0;
    i = (i + 1) % 16;
    snprintf(buf[i], sizeof(buf[i]), "%#010lx", (unsigned long)res);
    return buf[i];
}

// --- raw cecd:s IPC, following allfor0/netpass source/cecd.c exactly ---

static Result cecdsInitRaw(void) {
    return srvGetServiceHandle(&g_cecdHandle, "cecd:s");
}

static Result cecdStartCmd(u32 command) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x0B, 1, 0);
    cmdbuf[1] = command;
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

static Result cecdStopCmd(u32 command) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x0C, 1, 0);
    cmdbuf[1] = command;
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

static Result cecdGetCecdStateCmd(u32 *state) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x0E, 0, 0);
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    res = (Result)cmdbuf[1];
    if (state) *state = cmdbuf[2];
    return res;
}

static Result cecdGetChangeStateEventHandleCmd(Handle *handle) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x10, 0, 0);
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    res = (Result)cmdbuf[1];
    if (handle) *handle = cmdbuf[3];
    return res;
}

static Result waitForCecdState(bool start, u32 command, u32 want_state) {
    Handle ev;
    Result res = cecdGetChangeStateEventHandleCmd(&ev);
    if (R_FAILED(res)) return res;
    res = start ? cecdStartCmd(command) : cecdStopCmd(command);
    if (R_FAILED(res)) { svcCloseHandle(ev); return res; }
    for (int count = 0; count < 20; count++) {
        svcWaitSynchronization(ev, 10ULL * 1000000000ULL);
        u32 state = 0;
        res = cecdGetCecdStateCmd(&state);
        if (R_SUCCEEDED(res) && state == want_state) break;
    }
    svcCloseHandle(ev);
    return res;
}

static Result cecdSprCreate(void) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x40A, 0, 0);
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

static Result cecdSprInitialise(void) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x40B, 0, 0);
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

static Result cecdSprGetSlotsMetadata(u32 size, SlotMetadata *buf, u32 *slots_total) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x40C, 1, 2);
    cmdbuf[1] = size;
    cmdbuf[2] = IPC_Desc_Buffer(size, IPC_BUFFER_W);
    cmdbuf[3] = (u32)buf;
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    res = (Result)cmdbuf[1];
    if (slots_total) *slots_total = cmdbuf[2];
    return res;
}

static Result cecdSprFinaliseSend(void) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x40F, 0, 0);
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

static Result cecdSprStartRecv(void) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x410, 0, 0);
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

static Result cecdSprAddSlotsMetadata(u32 size, void *buf) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x411, 1, 2);
    cmdbuf[1] = size;
    cmdbuf[2] = IPC_Desc_Buffer(size, IPC_BUFFER_R);
    cmdbuf[3] = (u32)buf;
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

static Result cecdSprAddSlot(u32 title_id, u32 size, void *buf) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x412, 3, 2);
    cmdbuf[1] = title_id;
    cmdbuf[2] = 0xFF; // "flags" -- allfor0/netpass hardcodes this, meaning unknown
    cmdbuf[3] = size;
    cmdbuf[4] = IPC_Desc_Buffer(size, IPC_BUFFER_R);
    cmdbuf[5] = (u32)buf;
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

static Result cecdSprFinaliseRecv(void) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x413, 0, 0);
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

static Result cecdSprSetTitleSent(u32 title_id, bool success) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x40E, 2, 0);
    cmdbuf[1] = title_id;
    cmdbuf[2] = success;
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

static Result cecdSprDone(bool success) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x414, 1, 0);
    cmdbuf[1] = success;
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

// CEC_PATH_INBOX_INFO = 3 (docs.mikage.app/3dbrew CecDataPathType). Shared
// between cecd:u and cecd:s (3dbrew: "cecd:s ... contains a similar
// (probably the same) command handler from 0x0001.... to 0x0021.... as
// them in cecd:u"), so we can reuse the still-open g_cecdHandle.
#define CEC_PATH_INBOX_INFO 3u

// NetPass's own R_IS_CEC_RESTART check (source/api.c): right after an SPR
// session finishes, cecd:s needs a moment to leave "boss" mode, and any
// IPC call attempted too soon fails with this specific
// (Invalid_state, module=CEC) combination rather than a real error.
#define CTR_RESULT_SUMMARY(res) (((res) >> 21) & 0x3F)
#define CTR_RESULT_MODULE(res) (((res) >> 10) & 0xFF)
#define CTR_RESULT_SUMMARY_INVALID_STATE 5
#define CTR_RESULT_MODULE_CEC 66
#define IS_CEC_RESTART(res) (CTR_RESULT_SUMMARY(res) == CTR_RESULT_SUMMARY_INVALID_STATE && CTR_RESULT_MODULE(res) == CTR_RESULT_MODULE_CEC)

static Result cecdOpenAndReadRaw(void *readBuf, u32 readBufSize, u32 *readSize, u32 programId, u32 pathType) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x12, 4, 4);
    cmdbuf[1] = readBufSize;
    cmdbuf[2] = programId;
    cmdbuf[3] = pathType;
    cmdbuf[4] = 0;
    cmdbuf[5] = IPC_Desc_CurProcessId();
    cmdbuf[6] = 0;
    cmdbuf[7] = IPC_Desc_Buffer(readBufSize, IPC_BUFFER_W);
    cmdbuf[8] = (u32)readBuf;
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    res = (Result)cmdbuf[1];
    if (R_SUCCEEDED(res) && readSize) *readSize = cmdbuf[2];
    return res;
}

// CEC_PATH_MBOX_INFO = 2 (project findings, 2026-09-15 dynamic
// analysis confirmed CecMBoxInfoHeader's real layout, magic 0x6363 'cc',
// 96 bytes, matching allfor0/netpass's struct exactly). flag_unread is at
// offset 0x40, flag_new at 0x41.
#define CEC_PATH_MBOX_INFO 2u
#define MBOX_INFO_FLAG_UNREAD_OFFSET 0x40
#define MBOX_INFO_FLAG_NEW_OFFSET 0x41

static Result cecdOpenAndWriteRaw(const void *writeBuf, u32 writeBufSize, u32 programId, u32 pathType) {
    Result res;
    u32 *cmdbuf = getThreadCommandBuffer();
    cmdbuf[0] = IPC_MakeHeader(0x11, 4, 4);
    cmdbuf[1] = writeBufSize;
    cmdbuf[2] = programId;
    cmdbuf[3] = pathType;
    cmdbuf[4] = 0;
    cmdbuf[5] = IPC_Desc_CurProcessId();
    cmdbuf[6] = 0;
    cmdbuf[7] = IPC_Desc_Buffer(writeBufSize, IPC_BUFFER_R);
    cmdbuf[8] = (u32)writeBuf;
    if (R_FAILED(res = svcSendSyncRequest(g_cecdHandle))) return res;
    return (Result)cmdbuf[1];
}

int main(int argc, char *argv[]) {
    gfxInitDefault();
    consoleInit(GFX_TOP, NULL);

    g_log = fopen("sdmc:/spr_inject_log.txt", "w");
    if (!g_log) {
        printf("failed to open log file on sdmc\n");
        goto done;
    }

    writelog("=== spr_inject starting ===\n");

    // Load the pre-crafted TMP Box body (already proven to be silently
    // rejected over real WiFi StreetPass) from
    // the SD card. Generic filename: to try a different pre-generated
    // fresh-messageId box (mii_plaza_editor.py --new-ids), copy/rename it
    // to this exact path before running (each Mii Plaza launch consumes
    // a messageId's "never seen before" state, so reusing one gives a
    // confounded result -- project findings, 2026-09-15).
    const char *body_path = "sdmc:/streetpass_test/body_to_inject.bin";
    FILE *bf = fopen(body_path, "rb");
    if (!bf) {
        writelog("failed to open %s\n", body_path);
        printf("failed to open %s (see log)\n", body_path);
        goto close_log;
    }
    fseek(bf, 0, SEEK_END);
    long body_len = ftell(bf);
    fseek(bf, 0, SEEK_SET);
    writelog("loaded %s (%ld bytes)\n", body_path, body_len);

    u32 slot_size = (u32)(sizeof(CecSlotHeader) + body_len);
    u8 *slot_buf = malloc(slot_size);
    if (!slot_buf) {
        writelog("malloc(%lu) failed\n", (unsigned long)slot_size);
        fclose(bf);
        goto close_log;
    }
    CecSlotHeader *slot_hdr = (CecSlotHeader *)slot_buf;
    slot_hdr->magic = 0x6161;
    slot_hdr->padding = 0;
    slot_hdr->size = slot_size;
    slot_hdr->title_id = MII_PLAZA_TITLE_ID;
    slot_hdr->batch_id = 0;
    slot_hdr->message_count = 1;
    size_t nread = fread(slot_buf + sizeof(CecSlotHeader), 1, (size_t)body_len, bf);
    fclose(bf);
    writelog("read %lu of %ld bytes into slot buffer (total slot_size=%lu)\n",
         (unsigned long)nread, body_len, (unsigned long)slot_size);
    if ((long)nread != body_len) {
        writelog("short read, aborting\n");
        free(slot_buf);
        goto close_log;
    }

    Result res = cecdsInitRaw();
    writelog("cecdsInit(cecd:s): %s\n", rs(res));
    if (R_FAILED(res)) goto free_buf;

    // Hand normal continuous-scan control over to "boss"/SPR mode, same
    // as NetPass's waitForCecdState(false, CEC_COMMAND_OVER_BOSS, ...).
    res = waitForCecdState(false, CEC_COMMAND_OVER_BOSS, CEC_STATE_ABBREV_INACTIVE);
    writelog("waitForCecdState(OVER_BOSS -> INACTIVE): %s\n", rs(res));

    res = cecdSprCreate();
    writelog("cecdSprCreate: %s\n", rs(res));

    res = cecdSprInitialise();
    writelog("cecdSprInitialise: %s\n", rs(res));

    // We have nothing of our own to send -- still call GetSlotsMetadata +
    // FinaliseSend with an empty/oversized scratch buffer just to walk
    // the state machine through the send phase, same shape as NetPass's
    // real flow (which always does both phases every session). This time,
    // also keep the real entries: project findings candidate 4
    // follow-up (2026-09-15) -- our first attempt guessed send_method=0
    // for the crafted SlotMetadata and got silently discarded (InBox
    // BoxInfo num_messages stayed 0 despite every IPC call returning
    // success). Use whatever send_method real, currently-installed
    // StreetPass titles actually report instead of a guess.
    SlotMetadata send_meta[12];
    u32 slots_total = 0;
    res = cecdSprGetSlotsMetadata(sizeof(send_meta), send_meta, &slots_total);
    writelog("cecdSprGetSlotsMetadata: %s slots_total=%lu\n", rs(res), (unsigned long)slots_total);
    for (u32 i = 0; i < slots_total && i < 12; i++) {
        writelog("  real slot[%lu]: send_method=%d title_id=%#010lx size=%lu\n",
                 (unsigned long)i, send_meta[i].send_method,
                 (unsigned long)send_meta[i].title_id, (unsigned long)send_meta[i].size);
    }

    // project findings candidate 4, 2nd follow-up (2026-09-15):
    // reading gitlab.com/3ds-netpass/netpass source/api.c's real
    // doSlotExchange() flow (as opposed to just its function names)
    // showed a step this project's first attempt skipped entirely --
    // NetPass calls cecdSprSetTitleSent() for every real slot
    // GetSlotsMetadata returned, BEFORE FinaliseSend, even when it had
    // nothing of its own to upload for that title (uploadSlot() still
    // runs, just as a delete-only no-op for size==0/send_method==1
    // entries). Skipping this may have left CECD's internal SPR state
    // machine in a state that then silently discarded whatever this
    // project tried to receive afterward -- try mirroring it exactly.
    for (u32 i = 0; i < slots_total && i < 12; i++) {
        bool sent = send_meta[i].send_method != 1; // 1 = recv-only, nothing was sent
        Result sres = cecdSprSetTitleSent(send_meta[i].title_id, sent);
        writelog("  cecdSprSetTitleSent(title_id=%#010lx, sent=%d): %s\n",
                 (unsigned long)send_meta[i].title_id, sent, rs(sres));
    }

    res = cecdSprFinaliseSend();
    writelog("cecdSprFinaliseSend: %s\n", rs(res));

    res = cecdSprStartRecv();
    writelog("cecdSprStartRecv: %s\n", rs(res));

    // Template our crafted entry on a real one instead of guessing: prefer
    // an entry that's actually for Mii Plaza, otherwise just borrow
    // send_method from whichever real entry came back first.
    int template_send_method = 0;
    bool have_template = false;
    for (u32 i = 0; i < slots_total && i < 12; i++) {
        if (send_meta[i].title_id == MII_PLAZA_TITLE_ID) {
            template_send_method = send_meta[i].send_method;
            have_template = true;
            break;
        }
    }
    if (!have_template && slots_total > 0) {
        template_send_method = send_meta[0].send_method;
        have_template = true;
    }
    writelog("using send_method=%d for our crafted slot (from a real slot: %s)\n",
             template_send_method, have_template ? "yes" : "no, fell back to 0");

    SlotMetadata recv_meta = { .send_method = template_send_method, .title_id = MII_PLAZA_TITLE_ID, .size = slot_size };
    res = cecdSprAddSlotsMetadata(sizeof(recv_meta), &recv_meta);
    writelog("cecdSprAddSlotsMetadata: %s\n", rs(res));

    res = cecdSprAddSlot(MII_PLAZA_TITLE_ID, slot_size, slot_buf);
    writelog("cecdSprAddSlot: %s\n", rs(res));

    res = cecdSprFinaliseRecv();
    writelog("cecdSprFinaliseRecv: %s\n", rs(res));

    res = cecdSprDone(true);
    writelog("cecdSprDone(true): %s\n", rs(res));

    // project findings: cecdSprAddSlot/FinaliseRecv/Done all
    // returning success doesn't by itself prove the message actually
    // landed in Mii Plaza's real InBox list -- CECD could be silently
    // discarding it during finalisation the same way it silently
    // discards over WiFi. Read InBox___/BoxInfo_____ back and search for
    // our own messageId to tell the two apart.
    {
        static u8 inboxInfoBuf[4096];
        u32 readSize = 0;
        Result rres;
        for (int attempt = 0; attempt < 10; attempt++) {
            rres = cecdOpenAndReadRaw(inboxInfoBuf, sizeof(inboxInfoBuf), &readSize,
                                       MII_PLAZA_TITLE_ID, CEC_PATH_INBOX_INFO);
            if (R_SUCCEEDED(rres) || !IS_CEC_RESTART((u32)rres)) break;
            // cecd:s is still leaving "boss"/SPR mode -- close and reopen
            // the session and give it a moment, then retry (mirrors
            // NetPass's own R_IS_CEC_RESTART handling).
            writelog("cecdOpenAndRead(INBOX_INFO) attempt %d: CEC_RESTART (%s), reopening session and retrying\n",
                     attempt, rs(rres));
            svcCloseHandle(g_cecdHandle);
            svcSleepThread(200ULL * 1000000ULL);
            cecdsInitRaw();
        }
        writelog("cecdOpenAndRead(INBOX_INFO): %s readSize=%lu\n", rs(rres), (unsigned long)readSize);
        if (R_SUCCEEDED(rres) && readSize > 0) {
            writelog("InBox BoxInfo bytes:");
            for (u32 i = 0; i < readSize && i < sizeof(inboxInfoBuf); i++) writelog(" %02x", inboxInfoBuf[i]);
            writelog("\n");

            // messageId lives at offset 0x20 of the CecMessageHeader
            // (mii_plaza_editor.py's MESSAGE_ID_OFFSET), which sits right
            // after our own 20-byte CecSlotHeader wrapper in slot_buf --
            // read it back out of what we just sent instead of a
            // hardcoded constant, so this works for whichever
            // body_to_inject.bin was actually loaded.
            const u8 *our_message_id = slot_buf + sizeof(CecSlotHeader) + 0x20;
            bool found = false;
            for (u32 i = 0; i + 8 <= readSize; i++) {
                if (memcmp(inboxInfoBuf + i, our_message_id, 8) == 0) { found = true; break; }
            }
            writelog("our injected messageId (");
            for (int i = 0; i < 8; i++) writelog("%02x", our_message_id[i]);
            writelog(") found in InBox BoxInfo: %s\n", found ? "YES" : "NO");
        }
    }

    // project findings (2026-09-15): live GDB dump of Mii Plaza's
    // own OpenAndWrite call to CEC_PATH_MBOX_INFO right after it processed
    // our SPR-injected message showed flag_unread=0 and flag_new=0 --
    // even though InBox's own BoxInfo correctly showed num_messages=1.
    // Hypothesis: cecdSprAddSlot/FinaliseRecv updates the InBox's own
    // message list but never touches this separate per-title
    // "is there anything new" flag that a real WiFi-received StreetPass
    // write would normally set, and Mii Plaza's entrance-screen/new-
    // visitor UI gates on this flag rather than (or in addition to)
    // InBox's num_messages. Test directly: read MBoxInfo back, force
    // flag_unread/flag_new to 1, write it back.
    {
        static u8 mboxInfoBuf[128];
        u32 readSize = 0;
        Result rres = cecdOpenAndReadRaw(mboxInfoBuf, sizeof(mboxInfoBuf), &readSize,
                                          MII_PLAZA_TITLE_ID, CEC_PATH_MBOX_INFO);
        writelog("cecdOpenAndRead(MBOX_INFO): %s readSize=%lu\n", rs(rres), (unsigned long)readSize);
        if (R_SUCCEEDED(rres) && readSize >= 0x60) {
            writelog("MBoxInfo before: flag_unread=%d flag_new=%d\n",
                     mboxInfoBuf[MBOX_INFO_FLAG_UNREAD_OFFSET], mboxInfoBuf[MBOX_INFO_FLAG_NEW_OFFSET]);
            mboxInfoBuf[MBOX_INFO_FLAG_UNREAD_OFFSET] = 1;
            mboxInfoBuf[MBOX_INFO_FLAG_NEW_OFFSET] = 1;
            Result wres = cecdOpenAndWriteRaw(mboxInfoBuf, readSize, MII_PLAZA_TITLE_ID, CEC_PATH_MBOX_INFO);
            writelog("cecdOpenAndWrite(MBOX_INFO, flag_unread=1 flag_new=1): %s\n", rs(wres));

            // read back to confirm the write actually stuck
            memset(mboxInfoBuf, 0, sizeof(mboxInfoBuf));
            rres = cecdOpenAndReadRaw(mboxInfoBuf, sizeof(mboxInfoBuf), &readSize,
                                       MII_PLAZA_TITLE_ID, CEC_PATH_MBOX_INFO);
            writelog("cecdOpenAndRead(MBOX_INFO) verify: %s flag_unread=%d flag_new=%d\n",
                     rs(rres), mboxInfoBuf[MBOX_INFO_FLAG_UNREAD_OFFSET], mboxInfoBuf[MBOX_INFO_FLAG_NEW_OFFSET]);
        }
    }

    writelog("=== spr_inject finished -- now check Mii Plaza ===\n");

free_buf:
    free(slot_buf);
close_log:
    fclose(g_log);

done:
    printf("done, see sdmc:/spr_inject_log.txt\nnow open Mii Plaza\n");
    while (aptMainLoop()) {
        gspWaitForVBlank();
        hidScanInput();
        u32 kDown = hidKeysDown();
        if (kDown & KEY_START) break;
        gfxFlushBuffers();
        gfxSwapBuffers();
    }

    gfxExit();
    return 0;
}
