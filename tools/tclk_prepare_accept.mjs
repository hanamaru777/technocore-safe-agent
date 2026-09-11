// PREPARE-only bridge to the pinned official @flop-labs/tclk runtime.
// It never signs or posts. Hash-lock material is persisted once in the restricted
// signer state directory before any public preview is emitted and is never printed.
// If the public-preview write was interrupted, a later invocation reuses the existing
// preimage and accept nonce to reconstruct the exact same accept instead of minting
// replacement protocol material.
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import {
  dealRoom,
  decodeFrame,
  encodeFrame,
  generateHashLock,
  hashLockFromPreimage,
  makeAccept,
} from "@flop-labs/tclk";

const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX0X64 = /^0x[0-9a-f]{64}$/;
const NONCE = /^[0-9a-f]{8,64}$/;
const OFFER_ID = /^0x[0-9a-f]{64}$/;
const DID = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}$/;
const KEY = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const REQUIRED = new Set([
  "stage_id",
  "stage_digest",
  "offer_id",
  "offer_line",
  "frame_sha256",
  "job_id",
  "expires_ms",
  "from",
  "full_spec_sha256",
  "material_sha256",
]);
const PRIVATE_REQUIRED = new Set([
  "schema_version",
  "stage_id",
  "offer_id",
  "contract_id",
  "accept_nonce",
  "preimage",
]);

function fail() {
  throw new Error("prepare failed");
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hashLockStatement(preimage) {
  if (!HEX0X64.test(preimage)) fail();
  const lock = hashLockFromPreimage(preimage);
  if (!lock || lock.preimage !== preimage || !HEX0X64.test(lock.hash)) fail();
  return lock.hash;
}

function exactKeys(value, required = REQUIRED) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === required.size && keys.every((key) => required.has(key));
}

function acceptFromStatement(offer, from, statement, nonce = undefined) {
  if (!HEX0X64.test(statement)) fail();
  if (nonce !== undefined && !NONCE.test(nonce)) fail();
  const accept = makeAccept(offer, { from, statement, nonce });
  const acceptLine = encodeFrame(accept);
  return {
    accept,
    acceptLine,
    acceptSha256: sha256(acceptLine),
  };
}

let raw = "";
try {
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (Buffer.byteLength(raw, "utf8") > 16384) fail();
  }
  const input = JSON.parse(raw);
  if (!exactKeys(input)) fail();
  if (!HEX32.test(input.stage_id) || !HEX64.test(input.stage_digest)) fail();
  if (!OFFER_ID.test(input.offer_id) || !HEX64.test(input.frame_sha256)) fail();
  if (!KEY.test(input.job_id) || !DID.test(input.from)) fail();
  if (!HEX64.test(input.full_spec_sha256)) fail();
  if (input.material_sha256 !== null && !HEX64.test(input.material_sha256)) fail();
  if (!Number.isSafeInteger(input.expires_ms) || input.expires_ms <= Date.now()) fail();
  if (typeof input.offer_line !== "string" || input.offer_line.length > 4096) fail();
  if (sha256(input.offer_line) !== input.frame_sha256) fail();

  const offer = decodeFrame(input.offer_line);
  if (offer.type !== "offer" || offer.id !== input.offer_id) fail();
  // First real pilot is payee-side only. Under the pinned hash-lock choreography,
  // the payee mints the preimage at accept and the payer later locks the rail.
  if (offer.role !== "payer") fail();
  if (offer.lock !== "hash" || offer.rails.length !== 1 || offer.rails[0] !== "paper") fail();
  if (!offer.job || offer.job.proto !== "a2a" || offer.job.id !== input.job_id) fail();
  if (offer.expiresMs !== input.expires_ms || offer.from === input.from) fail();

  const stateRoot = process.env.FLOP_STATE_DIR;
  if (typeof stateRoot !== "string" || !path.isAbsolute(stateRoot)) fail();
  const privateDir = path.join(stateRoot, "signer", "tclk-pilot-secrets");
  mkdirSync(privateDir, { recursive: true, mode: 0o700 });
  chmodSync(privateDir, 0o700);
  const privateFile = path.join(privateDir, `${input.stage_id}.json`);

  let prepared;
  if (existsSync(privateFile)) {
    const stored = JSON.parse(readFileSync(privateFile, "utf8"));
    if (!exactKeys(stored, PRIVATE_REQUIRED) || stored.schema_version !== 1) fail();
    if (stored.stage_id !== input.stage_id || stored.offer_id !== input.offer_id) fail();
    if (!OFFER_ID.test(stored.contract_id) || !NONCE.test(stored.accept_nonce) || !HEX0X64.test(stored.preimage)) fail();
    prepared = acceptFromStatement(
      offer,
      input.from,
      hashLockStatement(stored.preimage),
      stored.accept_nonce,
    );
    if (prepared.accept.contract !== stored.contract_id) fail();
  } else {
    const minted = generateHashLock();
    if (!HEX0X64.test(minted.preimage) || !HEX0X64.test(minted.hash)) fail();
    if (hashLockStatement(minted.preimage) !== minted.hash) fail();
    prepared = acceptFromStatement(offer, input.from, minted.hash);
    if (!NONCE.test(prepared.accept.nonce)) fail();
    const fd = openSync(privateFile, "wx", 0o600);
    try {
      const privateRecord = JSON.stringify({
        schema_version: 1,
        stage_id: input.stage_id,
        offer_id: input.offer_id,
        contract_id: prepared.accept.contract,
        accept_nonce: prepared.accept.nonce,
        preimage: minted.preimage,
      });
      writeFileSync(fd, `${privateRecord}\n`, { encoding: "utf8" });
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
    frame_sha256: input.frame_sha256,
    full_spec_sha256: input.full_spec_sha256,
    material_sha256: input.material_sha256,
    expires_ms: input.expires_ms,
    accept_line: prepared.acceptLine,
    accept_sha256: prepared.acceptSha256,
    contract_id: prepared.accept.contract,
    deal_room: dealRoom(prepared.accept.contract),
  }));
} catch {
  process.stderr.write("tclk pilot prepare failed\n");
  process.exit(1);
}
