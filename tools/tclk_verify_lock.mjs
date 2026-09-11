// Read-only verifier for one already-accepted first-pilot tclk contract.
// Uses only pinned @flop-labs/tclk parsing/state-machine/PaperRail primitives.
// No network, signing, secret generation, note write, or protocol POST exists here.
import {
  OFFER_ROOM,
  transcriptRecord,
  findContractHandshake,
  foldTranscript,
  decodeFrame,
  dealRoom,
  lockTerms,
  paperNote,
  decodePaperRecord,
} from "@flop-labs/tclk";
import { createHash } from "node:crypto";

function sha256(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function fail(code = 2) {
  process.exit(code);
}

function normalizeRecords(room, rows) {
  if (!Array.isArray(rows) || rows.length > 200) throw new Error("records");
  let previous = -1;
  return rows.map((row) => {
    const record = transcriptRecord(room, row);
    if (record.seq <= previous) throw new Error("record_order");
    previous = record.seq;
    return record;
  });
}

let input;
try {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  input = JSON.parse(raw);
} catch {
  fail();
}

const expectedKeys = ["contract_id", "deal_records", "deal_room", "offer_records", "paper_note_value"];
if (
  !input || typeof input !== "object" || Array.isArray(input) ||
  Object.keys(input).sort().join(",") !== expectedKeys.sort().join(",") ||
  typeof input.contract_id !== "string" ||
  typeof input.deal_room !== "string" ||
  (input.paper_note_value !== null && typeof input.paper_note_value !== "string")
) {
  fail();
}

try {
  const derivedRoom = dealRoom(input.contract_id);
  if (derivedRoom !== input.deal_room) throw new Error("deal_room_binding");

  const offerRecords = normalizeRecords(OFFER_ROOM, input.offer_records);
  const handshake = findContractHandshake(offerRecords, input.contract_id);
  if (handshake === null) {
    process.stdout.write(JSON.stringify({
      ok: true,
      status: "accept_not_found",
      contract_id: input.contract_id,
      deal_room: derivedRoom,
      lock_verified: false,
    }));
    process.exit(0);
  }

  const offer = decodeFrame(handshake.offer.line);
  const accept = decodeFrame(handshake.accept.line);
  if (offer.type !== "offer" || accept.type !== "accept") throw new Error("handshake_type");
  if (accept.contract !== input.contract_id || accept.ref !== offer.id) throw new Error("handshake_binding");

  const dealRecords = normalizeRecords(derivedRoom, input.deal_records);
  const transcript = [handshake.offer, handshake.accept, ...dealRecords];
  const folded = foldTranscript(transcript);
  if (folded.state === null || folded.state.contract !== input.contract_id) {
    throw new Error("fold_contract");
  }

  let lockFrame = null;
  let lockRecord = null;
  for (let index = 2; index < transcript.length; index += 1) {
    const step = folded.steps[index];
    if (!step?.ok || step.type !== "lock") continue;
    const frame = decodeFrame(transcript[index].line);
    if (frame.type !== "lock" || frame.contract !== input.contract_id) continue;
    lockFrame = frame;
    lockRecord = transcript[index];
    break;
  }

  const location = paperNote(input.contract_id);
  let paperRecord = null;
  if (typeof input.paper_note_value === "string") {
    paperRecord = decodePaperRecord(input.paper_note_value);
  }

  let paperVerified = false;
  if (lockFrame !== null && folded.state.status === "locked") {
    const terms = lockTerms(folded.state);
    paperVerified = (
      lockFrame.rail === "paper" &&
      lockFrame.ref === terms.contract &&
      paperRecord !== null &&
      paperRecord.status === "locked" &&
      paperRecord.lock === terms.lock &&
      paperRecord.statement === terms.statement &&
      paperRecord.refundAfterMs === terms.refundAfterMs
    );
  }

  process.stdout.write(JSON.stringify({
    ok: true,
    status: folded.state.status,
    contract_id: input.contract_id,
    deal_room: derivedRoom,
    offer_id: offer.id,
    offer_from: offer.from,
    offer_role: offer.role,
    accept_from: accept.from,
    accept_nonce: handshake.accept.nonce,
    accept_seq: handshake.accept.seq,
    accept_timestamp_ms: handshake.accept.timestampMs,
    accept_line_sha256: sha256(handshake.accept.line),
    lock_present: lockFrame !== null,
    lock_verified: Boolean(lockFrame !== null && paperVerified),
    lock_from: lockFrame?.from ?? null,
    lock_rail: lockFrame?.rail ?? null,
    lock_ref: lockFrame?.ref ?? null,
    lock_seq: lockRecord?.seq ?? null,
    lock_timestamp_ms: lockRecord?.timestampMs ?? null,
    lock_line_sha256: lockRecord === null ? null : sha256(lockRecord.line),
    paper_note_namespace: location.ns,
    paper_note_key: location.key,
    paper_note_status: paperRecord?.status ?? null,
    paper_note_sha256: typeof input.paper_note_value === "string" ? sha256(input.paper_note_value) : null,
  }));
} catch (error) {
  const reason = error instanceof Error ? error.message : "verification_failed";
  process.stderr.write(`verify_error:${reason.slice(0, 160)}`);
  fail(4);
}
