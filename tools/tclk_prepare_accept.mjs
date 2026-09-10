// PREPARE-only bridge to the pinned official @flop-labs/tclk runtime.
// It never signs or posts. The minted hash preimage is written once to the restricted
// signer state directory before any public preview is emitted, and is never printed.
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import {
  dealRoom,
  decodeFrame,
  encodeFrame,
  generateHashLock,
  makeAccept,
} from "@flop-labs/tclk";

const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
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

function fail() {
  throw new Error("prepare failed");
}

function sha256(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function exactKeys(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === REQUIRED.size && keys.every((key) => REQUIRED.has(key));
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
  if (offer.lock !== "hash" || offer.rails.length !== 1 || offer.rails[0] !== "paper") fail();
  if (!offer.job || offer.job.proto !== "a2a" || offer.job.id !== input.job_id) fail();
  if (offer.expiresMs !== input.expires_ms || offer.from === input.from) fail();

  const stateRoot = process.env.FLOP_STATE_DIR;
  if (typeof stateRoot !== "string" || !path.isAbsolute(stateRoot)) fail();
  const secretDir = path.join(stateRoot, "signer", "tclk-pilot-secrets");
  mkdirSync(secretDir, { recursive: true, mode: 0o700 });
  chmodSync(secretDir, 0o700);

  const minted = generateHashLock();
  if (!/^0x[0-9a-f]{64}$/.test(minted.preimage) || !/^0x[0-9a-f]{64}$/.test(minted.hash)) fail();
  const accept = makeAccept(offer, { from: input.from, statement: minted.hash });
  const acceptLine = encodeFrame(accept);
  const acceptSha256 = sha256(acceptLine);

  const secretFile = path.join(secretDir, `${input.stage_id}.json`);
  const fd = openSync(secretFile, "wx", 0o600);
  try {
    const secretRecord = JSON.stringify({
      schema_version: 1,
      stage_id: input.stage_id,
      offer_id: input.offer_id,
      contract_id: accept.contract,
      preimage: minted.preimage,
    });
    writeFileSync(fd, `${secretRecord}\n`, { encoding: "utf8" });
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(secretFile, 0o600);

  process.stdout.write(JSON.stringify({
    stage_id: input.stage_id,
    stage_digest: input.stage_digest,
    offer_id: input.offer_id,
    frame_sha256: input.frame_sha256,
    full_spec_sha256: input.full_spec_sha256,
    material_sha256: input.material_sha256,
    expires_ms: input.expires_ms,
    accept_line: acceptLine,
    accept_sha256: acceptSha256,
    contract_id: accept.contract,
    deal_room: dealRoom(accept.contract),
  }));
} catch {
  process.stderr.write("tclk pilot prepare failed\n");
  process.exit(1);
}
