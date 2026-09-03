// Read-only bridge to the official @flop-labs/tclk parser/state machine.
// It receives only an untrusted frame line and never reads keys or posts.
import { openContract, tryDecodeFrame } from "@flop-labs/tclk";

let input;
try {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  input = JSON.parse(raw);
} catch {
  process.stdout.write('{"frame":null}');
  process.exit(0);
}
if (!input || Object.keys(input).length !== 1 || typeof input.text !== "string") {
  process.stdout.write('{"frame":null}');
  process.exit(0);
}
const frame = tryDecodeFrame(input.text);
if (!frame || frame.type !== "offer") {
  process.stdout.write('{"frame":null}');
  process.exit(0);
}
try {
  // Reuse the official initial state transition as a second fail-closed check.
  openContract(frame);
  process.stdout.write(JSON.stringify({ frame }));
} catch {
  process.stdout.write('{"frame":null}');
}
