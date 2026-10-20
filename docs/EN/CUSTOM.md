# Customizing Outgoing Data (`mii_plaza_editor.py`)

The box you send in step ② of §6 in [SETUP.md](SETUP.md) can be freely rewritten with
`scripts/mii_plaza_editor.py edit`. This file is a reference for the options of that `edit`
subcommand, organized by practical purpose. For field layouts see
[PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md).

```bash
python scripts/mii_plaza_editor.py edit <input.bin> <output.bin> [options...]
python scripts/mii_plaza_editor.py verify <output.bin>   # always check before sending
```

Make sure `outer HMAC` / `Mii CRC16` / `Mii CCM tag` are **all** `OK` in `verify` before sending.
If even one is `NG`, the console silently rejects it.

## Building a box from scratch (no template)

If you have no genuine box to start from, `scripts/build_tmp_box.py` generates one:

```bash
python scripts/build_tmp_box.py --mii my_mii.bin --comment "Hello!" -o box.bin
# or take the sender Mii from a picture of its Mii QR code (needs zbarimg or pyzbar):
python scripts/build_tmp_box.py --mii-qr my_mii_qr.png --comment "Hello!" -o box.bin
# optional: --smdh app.smdh | --title NAME | --large-icon img.png --small-icon img.png \
#           --header-icon img.png | --country 1 --region 41 | --counter N
```

`--mii` is a raw 96-byte FFLStoreData or a 112-byte encrypted Mii blob / Mii QR payload; `--mii-qr`
reads the QR code image the Mii Maker's "Send Miis" function creates for any Mii on the console (the CCM tag and CRC16 are verified, so a damaged or non-Mii
QR code is refused). A Mii from a real QR code has a genuine author_id / mii_id, which sidesteps the
problem that randomly generated IDs are refused. The
header, TLVs, body and HMAC trailer are generated; only the pieces Mii Plaza needs are filled in
(see [PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md)); the rest stays zero. Images are scaled to
the icon sizes (needs Pillow). The result can be checked without a console with
[EMULATOR_TEST.md](EMULATOR_TEST.md), and `mii_plaza_editor.py edit` can still be applied to it.
In code: `streetpass_emu.tmp_box_builder.BoxSpec` / `build_message`.
**Not yet tried on a real console.**

## Options to use every time

### `--new-ids`

Randomizes `messageId` / `messageId2` / `batchId` / `senderId` / `senderId2` / `created`.
**Always use it when re-sending the same box** — if `messageId` stays the same the console
de-duplicates it as already received and nothing happens (see the `messageId` entry in §7 of
[PROTOCOL_REFERENCE.md](PROTOCOL_REFERENCE.md)). It doesn't affect the identity (author_id /
mii_id), so combining it with `--set-mii-file` etc. does not change "who it is recognized as".

## Changing the sender Mii (who it is recognized as)

### `--set-mii-file <96-byte FFLStoreData file>`

Replaces the whole sender Mii. You can pass the file extracted from your own CFL_DB with
`scripts/extract_console_miis.py extract` ([SETUP.md](SETUP.md) §4.3) as-is — **everything is
replaced: face, nickname, creator and identity (author_id / mii_id)**. The console decides
based on "have I seen this `mii_id` before?":

- A Mii already in the CFL_DB (= already known to the console) → accepted as an "n-th meeting"
  (a re-encounter)
- A new author_id / mii_id the console has never seen (made with `--new-author-id` /
  `--new-mii-id` / `--set-identity` below) → accepted as a "first meeting" (a new visitor)

### `--new-author-id` / `--new-mii-id`

Keeps the sender Mii's face and nickname and replaces only one or both identity values with new
random ones (`--new-mii-id` generates a value that automatically satisfies the 3DS rule "the upper
nibble of the first byte is fixed to `0x9`"). Specifying both gives a completely different
identity and registers as a "first meeting" new visitor (confirmed on a real console).

### `--set-identity <author_id: 8 bytes hex> <mii_id: 10 bytes hex>`

Replaces them with specific values instead of random ones. Used for experiments that reuse another
console's genuine identity.

### `--set-mole 0|1`

Toggles only the face part "mole" on or off and recomputes the CRC16. It never changes
author_id / mii_id / nickname — an experiment-only option for isolating "change only the Mii
content while keeping the identity the same".

## Changing the message text

### `--comment "text"`

Rewrites the greeting comment. **Up to 16 characters** (the console's own input field limit).
Whatever length the original comment was, you can freely grow or shrink it up to 16 characters.

### `--notification-message "text"`

Rewrites the wording of the notification in the plaza (the equivalent of "Someone is here!").
It is a different field from `--comment` (the header's TLV extension area). It must be no longer
than the original string.

### `--body-header-title <TITLE_ID> <TITLE_VERSION> <NAME>`

Rewrites the "title that last set/updated the sender's console" information at the start of the
body (for example `0x0004001000020800 0x0001 "Mii Plaza"`). It's an investigative field with no
visible effect.

## Investigation / debugging (normally not needed)

### `--fuzz-unexplored-fields`

Randomizes `titleId2` / `unknown_1` / `messageVersion` / `flags` / `sendMethod` / `unopened` /
`newFlag` / `sendCount` / `forwardCount` / `userData` all at once. The console was confirmed to
accept it without problems. Use it only to re-confirm that these fields don't matter for
acceptance.

### `--comment-length-field <value>`

Rewrites just the unexplained u32 at the start of the comment field (the visible string is not
changed). Its meaning is still unknown and the field is left uninvestigated until it causes harm;
you don't need to touch it for normal customization.

## Combination examples

```bash
# Keep your own profile Mii, change only the comment, and re-send
python scripts/mii_plaza_editor.py edit template.bin out.bin \
    --new-ids --comment "Hi there!"

# Send as another Mii extracted from CFL_DB (e.g. someone you met before), with a comment
python scripts/mii_plaza_editor.py edit template.bin out.bin \
    --new-ids --set-mii-file other_mii.bin --comment "Nice to see you"

# Send as a completely different person (a new visitor)
python scripts/mii_plaza_editor.py edit template.bin out.bin \
    --new-ids --new-author-id --new-mii-id
```
