// Pure local PaperRail claim planner for the first genuine tclk/1 pilot.
// No network, filesystem or signing. Input contains the already-public reveal only
// after its authenticated deal-room POST is confirmed by the Python boundary.
import { createHash } from "node:crypto";
import {
  decodeFrame,
  decodePaperRecord,
  encodePaperRecord,
  paperNote,
  verifySecret,
} from "@flop-labs/tclk";

const CONTRACT = /^0x[0-9a-f]{64}$/;
const DID = /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{20,128}$/;

function fail() { throw new Error("paper claim plan failed"); }
function sha(value) { return createHash("sha256").update(value, "utf8").digest("hex"); }

let raw = "";
try {
  for await (const chunk of process.stdin) {
    raw += chunk;
    if (Buffer.byteLength(raw, "utf8") > 32768) fail();
  }
  const input = JSON.parse(raw);
  const keys = new Set(["contract_id", "our_did", "accept_line", "reveal_line", "current_note", "refund_after_ms", "now_ms"]);
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).length !== keys.size || !Object.keys(input).every(k => keys.has(k))) fail();
  if (!CONTRACT.test(input.contract_id) || !DID.test(input.our_did)) fail();
  if (typeof input.accept_line !== "string" || typeof input.reveal_line !== "string" || typeof input.current_note !== "string") fail();
  if (!Number.isSafeInteger(input.refund_after_ms) || !Number.isSafeInteger(input.now_ms)) fail();

  const accept = decodeFrame(input.accept_line);
  const reveal = decodeFrame(input.reveal_line);
  if (accept.type !== "accept" || accept.contract !== input.contract_id || accept.from !== input.our_did) fail();
  if (reveal.type !== "reveal" || reveal.contract !== input.contract_id || reveal.from !== input.our_did) fail();
  // Published @flop-labs/tclk 0.1.0 reveal wire intentionally has no ref field.
  if (!verifySecret("hash", accept.statement, reveal.secret)) fail();

  const current = decodePaperRecord(input.current_note);
  if (!current || current.lock !== "hash" || current.statement !== accept.statement || current.refundAfterMs !== input.refund_after_ms) fail();
  const loc = paperNote(input.contract_id);
  let status;
  let claimed;
  if (current.status === "claimed") {
    if (current.secret !== reveal.secret) fail();
    status = "already_claimed";
    claimed = input.current_note;
  } else if (current.status === "locked") {
    if (input.now_ms >= current.refundAfterMs) fail();
    status = "ready";
    claimed = encodePaperRecord({ ...current, status: "claimed", secret: reveal.secret });
  } else {
    fail();
  }
  process.stdout.write(JSON.stringify({
    status,
    namespace: loc.ns,
    key: loc.key,
    current_sha256: sha(input.current_note),
    claimed_line: claimed,
    claimed_sha256: sha(claimed),
    secret_sha256: sha(reveal.secret),
  }));
} catch {
  process.stderr.write("paper claim plan failed\n");
  process.exit(1);
}
