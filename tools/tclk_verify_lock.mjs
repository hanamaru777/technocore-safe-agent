// Read-only verifier for one already-accepted first-pilot tclk contract.
// Transport signatures are verified by the Python caller before records reach this bridge.
// This bridge uses only exports present in published @flop-labs/tclk 0.1.0 and independently
// enforces the pinned tclk/1 room/order/deadline/role/PaperRail semantics. No network or writes.
import {
  OFFER_ROOM,
  contractId,
  decodeFrame,
  dealRoom,
  paperNote,
  decodePaperRecord,
  verifySecret,
} from "@flop-labs/tclk";
import { createHash } from "node:crypto";

const TIMESTAMP = /^\d{4}-(?:0[1-9]|1[0-2])-(?:[0-2]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/;
const NONCE = /^(?:0|[1-9][0-9]*)$/;

function sha256(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function fail(code = 2) {
  process.exit(code);
}

function transportRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("record_shape");
  const keys = ["from", "nonce", "seq", "text", "ts"];
  if (Object.keys(value).sort().join(",") !== keys.sort().join(",")) throw new Error("record_shape");
  if (!Number.isSafeInteger(value.seq) || value.seq < 0) throw new Error("record_seq");
  if (typeof value.from !== "string" || typeof value.text !== "string") throw new Error("record_text");
  const nonce = String(value.nonce);
  if (!NONCE.test(nonce)) throw new Error("record_nonce");
  if (typeof value.ts !== "string" || !TIMESTAMP.test(value.ts)) throw new Error("record_ts");
  const timestampMs = Date.parse(value.ts);
  if (!Number.isSafeInteger(timestampMs) || timestampMs < 0) throw new Error("record_ts");
  return {...value, nonce, timestampMs};
}

function decodeBound(record) {
  const frame = decodeFrame(record.text);
  if (frame.from !== record.from) throw new Error("frame_sender_binding");
  return frame;
}

let input;
try {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  input = JSON.parse(raw);
} catch {
  fail();
}

const expectedKeys = ["accept_record", "contract_id", "deal_records", "deal_room", "offer_record", "paper_note_value"];
if (
  !input || typeof input !== "object" || Array.isArray(input) ||
  Object.keys(input).sort().join(",") !== expectedKeys.sort().join(",") ||
  typeof input.contract_id !== "string" || typeof input.deal_room !== "string" ||
  !Array.isArray(input.deal_records) || input.deal_records.length > 200 ||
  (input.paper_note_value !== null && typeof input.paper_note_value !== "string")
) {
  fail();
}

try {
  const derivedRoom = dealRoom(input.contract_id);
  if (derivedRoom !== input.deal_room) throw new Error("deal_room_binding");

  const offerRecord = transportRecord(input.offer_record);
  const acceptRecord = transportRecord(input.accept_record);
  if (offerRecord.seq >= acceptRecord.seq) throw new Error("handshake_order");

  const offer = decodeBound(offerRecord);
  const accept = decodeBound(acceptRecord);
  if (offer.type !== "offer" || accept.type !== "accept") throw new Error("handshake_type");
  if (offer.role !== "payer" || offer.lock !== "hash" || JSON.stringify(offer.rails) !== '["paper"]') {
    throw new Error("first_pilot_offer_terms");
  }
  if (accept.from === offer.from || accept.ref !== offer.id || acceptRecord.timestampMs >= offer.expiresMs) {
    throw new Error("accept_binding");
  }
  const expectedContract = contractId(offer, {
    from: accept.from,
    ref: accept.ref,
    statement: accept.statement,
    paymentKey: accept.paymentKey,
    nonce: accept.nonce,
  });
  if (accept.contract !== expectedContract || accept.contract !== input.contract_id) {
    throw new Error("contract_binding");
  }

  let state = "accepted";
  let lockFrame = null;
  let lockRecord = null;
  let previousSeq = -1;
  for (const rawRecord of input.deal_records) {
    const record = transportRecord(rawRecord);
    if (record.seq <= previousSeq) throw new Error("deal_record_order");
    previousSeq = record.seq;
    let frame;
    try {
      frame = decodeBound(record);
    } catch {
      continue;
    }
    if (frame.contract !== input.contract_id) continue;

    if (state === "accepted") {
      if (frame.type === "cancel" && (frame.from === offer.from || frame.from === accept.from)) {
        state = "cancelled";
        continue;
      }
      if (frame.type === "lock") {
        if (
          frame.from === offer.from && frame.rail === "paper" && frame.ref === input.contract_id &&
          record.timestampMs < offer.refundAfterMs
        ) {
          state = "locked";
          lockFrame = frame;
          lockRecord = record;
        }
        continue;
      }
      continue;
    }

    if (state === "locked") {
      if (
        frame.type === "reveal" && frame.from === accept.from &&
        (frame.ref === undefined || frame.ref === lockFrame.ref) &&
        record.timestampMs < offer.refundAfterMs && verifySecret(offer.lock, accept.statement, frame.secret)
      ) {
        state = "claimed";
        continue;
      }
      if (
        frame.type === "refund" && frame.from === offer.from &&
        (frame.ref === undefined || frame.ref === lockFrame.ref) &&
        record.timestampMs >= offer.refundAfterMs
      ) {
        state = "refunded";
      }
    }
  }

  const location = paperNote(input.contract_id);
  const paperRecord = typeof input.paper_note_value === "string"
    ? decodePaperRecord(input.paper_note_value)
    : null;

  const paperVerified = (
    state === "locked" && lockFrame !== null &&
    paperRecord !== null && paperRecord.status === "locked" &&
    paperRecord.lock === offer.lock &&
    paperRecord.statement === accept.statement &&
    paperRecord.refundAfterMs === offer.refundAfterMs
  );

  process.stdout.write(JSON.stringify({
    ok: true,
    status: state,
    contract_id: input.contract_id,
    deal_room: derivedRoom,
    offer_id: offer.id,
    offer_from: offer.from,
    offer_role: offer.role,
    accept_from: accept.from,
    accept_nonce: acceptRecord.nonce,
    accept_seq: acceptRecord.seq,
    accept_timestamp_ms: acceptRecord.timestampMs,
    accept_line_sha256: sha256(acceptRecord.text),
    lock_present: lockFrame !== null,
    lock_verified: Boolean(paperVerified),
    lock_from: lockFrame?.from ?? null,
    lock_rail: lockFrame?.rail ?? null,
    lock_ref: lockFrame?.ref ?? null,
    lock_seq: lockRecord?.seq ?? null,
    lock_timestamp_ms: lockRecord?.timestampMs ?? null,
    lock_line_sha256: lockRecord === null ? null : sha256(lockRecord.text),
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
