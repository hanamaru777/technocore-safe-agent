// Read-only verifier for one terminal first-pilot tclk PaperRail contract.
// The Python caller verifies Technocore transport signatures before records reach here.
// This bridge independently applies the pinned published tclk state machine and PaperRail
// decoding. It performs no network I/O and emits only public-safe hashes, never the witness.
import {
  applyFrame,
  contractId,
  decodeFrame,
  decodePaperRecord,
  dealRoom,
  openContract,
  paperNote,
  verifySecret,
} from "@flop-labs/tclk";
import { createHash } from "node:crypto";

const TIMESTAMP = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/;

function sha256(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function fail(reason = "verification_failed") {
  process.stderr.write(`terminal_verify_error:${String(reason).slice(0, 160)}`);
  process.exit(4);
}

function timestampMs(text) {
  if (typeof text !== "string" || !TIMESTAMP.test(text)) throw new Error("record_timestamp_invalid");
  const value = Date.parse(text);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("record_timestamp_invalid");
  return value;
}

function record(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("record_shape");
  const keys = ["from", "seq", "text", "ts"];
  if (Object.keys(value).sort().join(",") !== keys.join(",")) throw new Error("record_shape");
  if (!Number.isSafeInteger(value.seq) || value.seq < 0) throw new Error("record_seq");
  if (typeof value.from !== "string" || typeof value.text !== "string") throw new Error("record_text");
  return {...value, timestampMs: timestampMs(value.ts)};
}

let input;
try {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  input = JSON.parse(raw);
} catch {
  fail("input_invalid");
}

const expectedKeys = [
  "accept_line", "accept_timestamp_ms", "contract_id", "deal_records", "deal_room",
  "offer_line", "paper_note_value",
];
if (
  !input || typeof input !== "object" || Array.isArray(input) ||
  Object.keys(input).sort().join(",") !== expectedKeys.sort().join(",") ||
  typeof input.offer_line !== "string" || typeof input.accept_line !== "string" ||
  typeof input.contract_id !== "string" || typeof input.deal_room !== "string" ||
  !Number.isSafeInteger(input.accept_timestamp_ms) || input.accept_timestamp_ms < 0 ||
  !Array.isArray(input.deal_records) || input.deal_records.length > 200 ||
  typeof input.paper_note_value !== "string"
) {
  fail("input_invalid");
}

try {
  const offer = decodeFrame(input.offer_line);
  const accept = decodeFrame(input.accept_line);
  if (offer.type !== "offer" || accept.type !== "accept") throw new Error("handshake_type");
  if (offer.role !== "payer" || offer.lock !== "hash" || JSON.stringify(offer.rails) !== '["paper"]') {
    throw new Error("first_pilot_terms");
  }
  if (!offer.job || offer.job.proto !== "a2a" || typeof offer.job.id !== "string") throw new Error("job_binding");
  if (accept.from === offer.from || accept.ref !== offer.id || input.accept_timestamp_ms >= offer.expiresMs) {
    throw new Error("accept_binding");
  }
  const expectedContract = contractId(offer, {
    from: accept.from,
    ref: accept.ref,
    statement: accept.statement,
    paymentKey: accept.paymentKey,
    nonce: accept.nonce,
  });
  if (accept.contract !== expectedContract || accept.contract !== input.contract_id) throw new Error("contract_binding");
  if (dealRoom(input.contract_id) !== input.deal_room) throw new Error("deal_room_binding");

  let state = applyFrame(openContract(offer), accept, input.accept_timestamp_ms).state;
  if (state.status !== "accepted") throw new Error("accept_transition_invalid");

  let lockRecord = null;
  let revealRecord = null;
  let revealFrame = null;
  let receiptRecord = null;
  let previousSeq = -1;

  for (const rawRecord of input.deal_records) {
    const row = record(rawRecord);
    if (row.seq <= previousSeq) throw new Error("deal_record_order_invalid");
    previousSeq = row.seq;
    let frame;
    try {
      frame = decodeFrame(row.text);
    } catch {
      continue;
    }
    if (frame.from !== row.from || frame.contract !== input.contract_id) continue;
    const before = state.status;
    const step = applyFrame(state, frame, row.timestampMs);
    if (!step.ok) continue;
    state = step.state;

    if (frame.type === "lock" && before === "accepted" && state.status === "locked") {
      lockRecord = {row, frame};
      continue;
    }
    if (frame.type === "reveal" && before === "locked" && state.status === "claimed") {
      revealRecord = row;
      revealFrame = frame;
      continue;
    }
    if (frame.type === "receipt" && before === "claimed" && state.status === "claimed" && receiptRecord === null) {
      receiptRecord = {row, frame};
    }
  }

  if (state.status !== "claimed" || lockRecord === null || revealRecord === null || revealFrame === null) {
    throw new Error("terminal_not_claimed");
  }
  if (
    lockRecord.frame.from !== offer.from || lockRecord.frame.rail !== "paper" ||
    lockRecord.frame.ref !== input.contract_id
  ) throw new Error("lock_binding");
  if (revealFrame.from !== accept.from) throw new Error("reveal_party_invalid");
  if (revealFrame.ref !== undefined && revealFrame.ref !== input.contract_id) throw new Error("reveal_ref_invalid");

  const witness = revealFrame["secret"];
  if (typeof witness !== "string" || !verifySecret("hash", accept.statement, witness)) {
    throw new Error("reveal_witness_invalid");
  }

  const paper = decodePaperRecord(input.paper_note_value);
  if (
    paper === null || paper.status !== "claimed" || paper.lock !== "hash" ||
    paper.statement !== accept.statement || paper.refundAfterMs !== offer.refundAfterMs ||
    paper["secret"] !== witness || !verifySecret("hash", accept.statement, paper["secret"])
  ) throw new Error("paper_claim_invalid");

  const location = paperNote(input.contract_id);
  const receipt = receiptRecord === null ? null : {
    from: receiptRecord.row.from,
    line_sha256: sha256(receiptRecord.row.text),
    seq: receiptRecord.row.seq,
    ts: receiptRecord.row.ts,
  };

  process.stdout.write(JSON.stringify({
    ok: true,
    status: "claimed",
    offer_id: offer.id,
    payer_did: offer.from,
    payee_did: accept.from,
    job_id: offer.job.id,
    contract_id: input.contract_id,
    deal_room: input.deal_room,
    accept_line_sha256: sha256(input.accept_line),
    lock_from: lockRecord.row.from,
    lock_ref: lockRecord.frame.ref,
    lock_line_sha256: sha256(lockRecord.row.text),
    lock_seq: lockRecord.row.seq,
    lock_ts: lockRecord.row.ts,
    reveal_from: revealRecord.from,
    reveal_line_sha256: sha256(revealRecord.text),
    reveal_seq: revealRecord.seq,
    reveal_ts: revealRecord.ts,
    witness_sha256: sha256(witness),
    paper_note_namespace: location.ns,
    paper_note_key: location.key,
    paper_note_sha256: sha256(input.paper_note_value),
    receipt,
  }));
} catch (error) {
  fail(error instanceof Error ? error.message : "verification_failed");
}
