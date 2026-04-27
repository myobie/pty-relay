import {
  ready,
  parseToken,
  computeSecretHash,
  getWebSocketUrl,
  Handshake,
  NK,
  Transport,
} from "../crypto/index.ts";
import WebSocket from "ws";
import { log } from "../log.ts";

export async function list(tokenUrl: string): Promise<void> {
  await ready();
  log("cli", "list (one-shot token) begin");

  const parsed = parseToken(tokenUrl);
  const secretHash = computeSecretHash(parsed.secret);
  const wsUrl = getWebSocketUrl(parsed.host, "client", secretHash);

  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    ws.binaryType = "nodebuffer";

    let initiator: Handshake | null = null;
    let transport: Transport | null = null;

    ws.onopen = () => {};

    ws.onmessage = (event) => {
      if (typeof event.data === "string") {
        const msg = JSON.parse(event.data);
        if (msg.type === "paired") {
          initiator = new Handshake({
            pattern: NK,
            initiator: true,
            remoteStaticPublicKey: parsed.publicKey,
          });
          ws.send(initiator.writeMessage());
        } else if (msg.type === "error") {
          console.error(`Error: ${msg.message}`);
          ws.close();
          reject(new Error(msg.message));
        }
      } else {
        const data = Buffer.isBuffer(event.data) ? event.data : Buffer.from(event.data as ArrayBuffer);

        if (!transport && initiator) {
          initiator.readMessage(new Uint8Array(data));
          transport = new Transport(initiator.split());
          initiator = null;

          // Send list request
          const msg = JSON.stringify({ type: "list" });
          const ct = transport.encrypt(new TextEncoder().encode(msg));
          ws.send(ct);
        } else if (transport) {
          // decrypt throws on tag-verify failure (corrupt / replayed
          // ciphertext). Turn that into a clean promise rejection
          // rather than letting it escape ws.onmessage as an
          // uncaught exception.
          let plaintext: Uint8Array;
          try {
            plaintext = transport.decrypt(new Uint8Array(data));
          } catch (err: any) {
            ws.close();
            reject(new Error(`decrypt failed: ${err?.message ?? err}`));
            return;
          }
          try {
            const msg = JSON.parse(new TextDecoder().decode(plaintext));
            if (msg.type === "sessions") {
              displaySessions(msg.sessions, parsed.host);
              ws.close();
              resolve();
            }
          } catch {}
        }
      }
    };

    ws.onerror = (err) => {
      reject(new Error(`Connection failed: ${err.message}`));
    };

    ws.onclose = () => {};

    setTimeout(() => {
      ws.close();
      reject(new Error("Timeout waiting for session list"));
    }, 15000);
  });
}

function displaySessions(
  sessions: Array<{ name: string; status: string; command?: string; cwd?: string }>,
  host: string
) {
  if (sessions.length === 0) {
    console.log("No running sessions.");
    return;
  }

  console.log(`\x1b[1m${host}\x1b[0m`);
  for (const s of sessions) {
    const cmd = s.command || "";
    console.log(`  ${s.name.padEnd(20)} ${cmd.padEnd(20)} ${s.status}`);
  }
}
