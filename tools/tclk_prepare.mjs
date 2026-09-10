// Read-only/no-POST bridge used only by the signer-side tclk PREPARE process.
// It may return the freshly minted hash-lock secret to its parent process, which
// immediately persists it in signer-private mode 0600 state. It never reads keys,
// signs transport messages, performs network I/O, or posts anything.
import {
  decodeFrame,
  generateHashLock,
  makeAccept,
  encodeFrame,
  dealRoom,
} from "@flop-labs/tclk";
import { createHash } from "node:crypto";

let input;
try {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  input = JSON.parse(raw);
} catch {
  process.exit(2);
}
if (!input || Object.keys(input).sort().join(",") !== "from,offer" || typeof input.offer !== "string" || typeof input.from !== "string") {
  process.exit(2);
}
try {
  const offer = decodeFrame(input.offer);
  if (offer.type !== "offer" || offer.lock !== "hash" || JSON.stringify(offer.rails) !== '["paper"]' || offer.job?.proto !== "a2a") {
    process.exit(3);
  }
  if (!/^did:key:z6Mk[A-Za-z0-9]{44}$/.test(input.from) || input.from === offer.from) {
    process.exit(3);
  }
  const minted = generateHashLock();
  const accept = makeAccept(offer, { from: input.from, statement: minted.hash });
  const acceptLine = encodeFrame(accept);
  const acceptSha256 = createHash("sha256").update(acceptLine, "utf8").digest("hex");
  process.stdout.write(JSON.stringify({
    accept_line: acceptLine,
    accept_sha256: acceptSha256,
    contract: accept.contract,
    deal_room: dealRoom(accept.contract),
    secret: minted.preimage,
  }));
} catch {
  process.exit(4);
}
