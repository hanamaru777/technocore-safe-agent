// PREPARE-only reveal bridge for the first genuine tclk/1 PaperRail pilot.
// It reads the existing signer-private accept preimage, proves that it opens the
// accepted hash statement, constructs the exact reveal frame with the published
// @flop-labs/tclk runtime, persists that frame only in a 0600 signer-private file,
// and returns only public hashes/bindings. It never signs, posts, or writes a Note.
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import {
  dealRoom,
  decodeFrame,
  encodeFrame,
  hashLockFromPreimage,
  validateFrame,
} from "@flop-labs/tclk";

const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX0X64 = /^0x[0-9a-f]{64}$/;
const DID = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}$/;
const CONTRACT = /^0x[0-9a-f]{64}$/;
const ROOM = /^mb-p-tclk-[0-9a-f]{16}$/;
const KEY = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const MIN_CLAIM_MARGIN_MS = 120000;

const REQUIRED = new Set([
  "stage_id", "stage_digest", "offer_id", "offer_line", "counterpart_did", "our_did", "job_id",
  "accept_line", "accept_sha256", "contract_id", "deal_room",
  "lock_line_sha256", "lock_ref", "paper_note_sha256",
  "work_evidence_sha256", "expires_ms",
]);
const ACCEPT_PRIVATE_REQUIRED = new Set([
  "schema_version", "stage_id", "offer_id", "contract_id", "accept_nonce", "preimage",
]);
const REVEAL_PRIVATE_REQUIRED = new Set([
  "schema_version", "stage_id", "stage_digest", "offer_id", "counterpart_did", "our_did", "job_id",
  "contract_id", "lock_ref", "accept_sha256", "lock_line_sha256", "work_evidence_sha256",
  "claim_by_ms", "refund_after_ms", "reveal_line", "reveal_sha256",
]);

function fail() {
  throw new Error("reveal prepare failed");
}

function exactKeys(value, required) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === required.size && keys.every((key) => required.has(key));
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function require0600(file) {
  const mode = statSync(file).mode & 0o777;
  if (mode !== 0o600) fail();
}

function revealFrom(preimage, from, contract, ref) {
  if (!HEX0X64.test(preimage) || !DID.test(from) || !CONTRACT.test(contract) || !CONTRACT.test(ref)) fail();
  if (ref !== contract) fail();
  const revealInput = { type: "reveal", from, contract, ref };
  revealInput["secret"] = preimage;
  const reveal = validateFrame(revealInput);
  if (
    reveal.type !== "reveal"
    || reveal.from !== from
    || reveal.contract !== contract
    || reveal.ref !== ref
    || reveal.secret !== preimage
  ) fail();
  const line = encodeFrame(reveal);
  return { line, hash: sha256(line) };
}

let raw = "";
try {
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (Buffer.byteLength(raw, "utf8") > 32768) fail();
  }
  const input = JSON.parse(raw);
  if (!exactKeys(input, REQUIRED)) fail();
  if (!HEX32.test(input.stage_id) || !HEX64.test(input.stage_digest)) fail();
  if (!CONTRACT.test(input.offer_id) || !DID.test(input.counterpart_did) || !DID.test(input.our_did)) fail();
  if (input.counterpart_did === input.our_did || !KEY.test(input.job_id)) fail();
  if (!HEX64.test(input.accept_sha256) || !CONTRACT.test(input.contract_id) || !ROOM.test(input.deal_room)) fail();
  if (!HEX64.test(input.lock_line_sha256) || !CONTRACT.test(input.lock_ref) || !HEX64.test(input.paper_note_sha256)) fail();
  if (!HEX64.test(input.work_evidence_sha256) || !Number.isSafeInteger(input.expires_ms)) fail();
  if (typeof input.offer_line !== "string" || typeof input.accept_line !== "string") fail();
  if (sha256(input.accept_line) !== input.accept_sha256) fail();

  const offer = decodeFrame(input.offer_line);
  const accept = decodeFrame(input.accept_line);
  if (
    offer.type !== "offer"
    || offer.id !== input.offer_id
    || offer.role !== "payer"
    || offer.from !== input.counterpart_did
    || offer.from === input.our_did
  ) fail();
  if (offer.lock !== "hash" || !Array.isArray(offer.rails) || offer.rails.length !== 1 || offer.rails[0] !== "paper") fail();
  if (!offer.job || offer.job.proto !== "a2a" || offer.job.id !== input.job_id) fail();
  if (offer.expiresMs !== input.expires_ms) fail();
  if (accept.type !== "accept" || accept.from !== input.our_did || accept.ref !== offer.id) fail();
  if (accept.contract !== input.contract_id || dealRoom(accept.contract) !== input.deal_room) fail();
  if (input.lock_ref !== input.contract_id) fail();
  if (!Number.isSafeInteger(offer.claimByMs) || !Number.isSafeInteger(offer.refundAfterMs)) fail();
  if (offer.claimByMs >= offer.refundAfterMs || Date.now() + MIN_CLAIM_MARGIN_MS >= offer.claimByMs) fail();

  const stateRoot = process.env.FLOP_STATE_DIR;
  if (typeof stateRoot !== "string" || !path.isAbsolute(stateRoot)) fail();
  const acceptFile = path.join(stateRoot, "signer", "tclk-pilot-secrets", `${input.stage_id}.json`);
  if (!existsSync(acceptFile)) fail();
  require0600(acceptFile);
  const acceptPrivate = JSON.parse(readFileSync(acceptFile, "utf8"));
  if (!exactKeys(acceptPrivate, ACCEPT_PRIVATE_REQUIRED) || acceptPrivate.schema_version !== 1) fail();
  if (
    acceptPrivate.stage_id !== input.stage_id
    || acceptPrivate.offer_id !== input.offer_id
    || acceptPrivate.contract_id !== input.contract_id
    || acceptPrivate.accept_nonce !== accept.nonce
  ) fail();
  if (!HEX0X64.test(acceptPrivate.preimage)) fail();
  const lock = hashLockFromPreimage(acceptPrivate.preimage);
  if (!lock || lock.preimage !== acceptPrivate.preimage || lock.hash !== accept.statement) fail();

  const reveal = revealFrom(acceptPrivate.preimage, input.our_did, input.contract_id, input.lock_ref);
  const privateDir = path.join(stateRoot, "signer", "tclk-pilot-reveals");
  mkdirSync(privateDir, { recursive: true, mode: 0o700 });
  chmodSync(privateDir, 0o700);
  const privateFile = path.join(privateDir, `${input.stage_id}.json`);

  const expectedPrivate = {
    schema_version: 1,
    stage_id: input.stage_id,
    stage_digest: input.stage_digest,
    offer_id: input.offer_id,
    counterpart_did: input.counterpart_did,
    our_did: input.our_did,
    job_id: input.job_id,
    contract_id: input.contract_id,
    lock_ref: input.lock_ref,
    accept_sha256: input.accept_sha256,
    lock_line_sha256: input.lock_line_sha256,
    work_evidence_sha256: input.work_evidence_sha256,
    claim_by_ms: offer.claimByMs,
    refund_after_ms: offer.refundAfterMs,
    reveal_line: reveal.line,
    reveal_sha256: reveal.hash,
  };

  if (existsSync(privateFile)) {
    require0600(privateFile);
    const stored = JSON.parse(readFileSync(privateFile, "utf8"));
    if (!exactKeys(stored, REVEAL_PRIVATE_REQUIRED) || stored.schema_version !== 1) fail();
    if (JSON.stringify(stored) !== JSON.stringify(expectedPrivate)) fail();
  } else {
    const fd = openSync(privateFile, "wx", 0o600);
    try {
      writeFileSync(fd, `${JSON.stringify(expectedPrivate)}\n`, { encoding: "utf8" });
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    chmodSync(privateFile, 0o600);
  }

  process.stdout.write(JSON.stringify({
    stage_id: input.stage_id,
    stage_digest: input.stage_digest,
    offer_id: input.offer_id,
    counterpart_did: input.counterpart_did,
    our_did: input.our_did,
    job_id: input.job_id,
    contract_id: input.contract_id,
    deal_room: input.deal_room,
    accept_sha256: input.accept_sha256,
    lock_line_sha256: input.lock_line_sha256,
    lock_ref: input.lock_ref,
    paper_note_sha256: input.paper_note_sha256,
    work_evidence_sha256: input.work_evidence_sha256,
    expires_ms: input.expires_ms,
    claim_by_ms: offer.claimByMs,
    refund_after_ms: offer.refundAfterMs,
    reveal_sha256: reveal.hash,
  }));
} catch {
  process.stderr.write("tclk reveal prepare failed\n");
  process.exit(1);
}
