import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { WebSocketServer, type WebSocket } from "ws";
import { PairingRegistry } from "./pairing.ts";
import * as fs from "node:fs";
import * as path from "node:path";
import { URL } from "node:url";
import { log } from "../log.ts";

/**
 * Self-hosted relay server. Same WebSocket protocol as the Elixir relay --
 * clients can't tell the difference. No auth, no database, no email.
 * Designed for local networks and tailscale.
 *
 * Multi-client model:
 * - daemon connects with role=daemon (no client_id) -> primary control socket
 * - client connects with role=client -> gets assigned a client_id
 * - daemon connects with role=daemon&client_id=X -> per-client data socket
 */
export interface RelayServerOptions {
  /** When true, serve index.html with `<meta name="pty-relay-config"
   *  content='{"latencyStats":true}'>` injected so the web UI runs
   *  the latency tracker. When false (default), the web UI sees
   *  `latencyStats:false` and skips all telemetry. */
  latencyStats?: boolean;
}

export function createRelayServer(
  port: number,
  htmlPath?: string,
  host?: string,
  serverOpts: RelayServerOptions = {}
) {
  const registry = new PairingRegistry();

  // Read HTML for web UI serving. Inject the runtime config as a
  // <meta> tag so the web UI can read it on init. We do this once at
  // startup since index.html is already cached in memory; the price
  // of that caching is that toggling the flag requires a daemon
  // restart, which is fine for an opt-in dev/debug feature.
  let html = "<html><body>pty-relay self-hosted</body></html>";
  if (htmlPath && fs.existsSync(htmlPath)) {
    html = fs.readFileSync(htmlPath, "utf-8");
    const config = JSON.stringify({
      latencyStats: !!serverOpts.latencyStats,
    });
    const metaTag = `<meta name="pty-relay-config" content='${config}'>`;
    // Inject right before </head> so the meta is parsed before main.js
    // runs. If the placeholder isn't present (different HTML), append
    // before </body> as a fallback so we never silently drop the config.
    if (html.includes("</head>")) {
      html = html.replace("</head>", `  ${metaTag}\n</head>`);
    } else if (html.includes("</body>")) {
      html = html.replace("</body>", `${metaTag}\n</body>`);
    }
  }

  // Directory containing the built web UI (index.html, main.js, vendor/).
  const distDir = htmlPath ? path.dirname(htmlPath) : null;

  const httpServer = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url || "/", `http://localhost:${port}`);

    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"status":"ok"}');
    } else if (url.pathname.startsWith("/vendor/")) {
      // Serve vendor files — validate path stays within vendor directory
      const vendorDir = path.resolve(distDir ?? ".", "vendor");
      const vendorPath = path.resolve(vendorDir, path.basename(url.pathname));
      if (vendorPath.startsWith(vendorDir + path.sep) && fs.existsSync(vendorPath)) {
        const ext = path.extname(vendorPath);
        const ct = ext === ".mjs" ? "application/javascript" : ext === ".css" ? "text/css" : "application/octet-stream";
        res.writeHead(200, { "Content-Type": ct });
        fs.createReadStream(vendorPath).pipe(res);
      } else {
        res.writeHead(404);
        res.end("Not found");
      }
    } else if (url.pathname === "/main.js" && distDir) {
      // Serve the bundled browser entrypoint produced by `npm run build:browser`.
      const mainPath = path.resolve(distDir, "main.js");
      if (
        mainPath.startsWith(distDir + path.sep) &&
        fs.existsSync(mainPath)
      ) {
        res.writeHead(200, { "Content-Type": "application/javascript" });
        fs.createReadStream(mainPath).pipe(res);
      } else {
        res.writeHead(404);
        res.end("Not found");
      }
    } else {
      // Serve web UI for everything else
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(html);
    }
  });

  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });

  wss.on("connection", (ws: WebSocket, req: IncomingMessage) => {
    // Disable Nagle on the underlying TCP socket. Node + the `ws`
    // library default this to true since Node 16, but being explicit
    // matters when small WS frames (single-keystroke echo, ~3 bytes)
    // are the latency-sensitive payload — Nagle would otherwise
    // batch them for up to 40ms before sending. Belt-and-suspenders.
    try {
      req.socket.setNoDelay(true);
    } catch {
      // Some socket implementations (e.g. unusual proxy stacks)
      // don't support setNoDelay. Ignore — best-effort.
    }
    const url = new URL(req.url || "/", `http://localhost:${port}`);
    const role = url.searchParams.get("role");
    const secretHash = url.searchParams.get("secret_hash");
    const clientId = url.searchParams.get("client_id");
    const label = url.searchParams.get("label");
    const clientToken = url.searchParams.get("client_token");

    log("pairing", "ws connection", {
      role,
      hasSecretHash: !!secretHash,
      clientId,
      hasClientToken: !!clientToken,
      remote: req.socket.remoteAddress,
    });

    if (!role || !secretHash || (role !== "daemon" && role !== "client")) {
      log("pairing", "ws reject invalid params", { role });
      ws.close(4000, "invalid params");
      return;
    }

    if (secretHash.length !== 64) {
      log("pairing", "ws reject bad secret_hash length", { len: secretHash.length });
      ws.close(4000, "invalid secret_hash");
      return;
    }

    if (role === "daemon" && clientId) {
      // Per-client daemon socket: pair with an existing waiting client
      const ok = registry.registerDaemonForClient(secretHash, clientId, ws);
      log("pairing", "registerDaemonForClient", { clientId, ok });
      if (!ok) {
        ws.send(JSON.stringify({ type: "error", message: "client not found" }));
        ws.close();
      }
    } else if (role === "daemon") {
      // Primary daemon control socket
      const ok = registry.registerDaemon(secretHash, ws, label);
      log("pairing", "registerDaemon", { ok, label });
      if (!ok) {
        ws.send(JSON.stringify({ type: "error", message: "secret_hash already registered" }));
        ws.close();
      }
    } else {
      // Client connection — capture network metadata for the approval queue
      const forwarded = req.headers["x-forwarded-for"];
      const forwardedStr = Array.isArray(forwarded)
        ? forwarded[0]
        : forwarded;
      const remoteAddr =
        (forwardedStr ? forwardedStr.split(",")[0].trim() : null) ||
        req.socket.remoteAddress ||
        null;
      const userAgentHeader = req.headers["user-agent"];
      const userAgent =
        typeof userAgentHeader === "string" ? userAgentHeader : null;
      const originHeader = req.headers["origin"];
      const origin =
        typeof originHeader === "string" ? originHeader : null;

      const id = registry.registerClient(
        secretHash,
        ws,
        clientToken ?? undefined,
        { remoteAddr, userAgent, origin }
      );
      log("pairing", "registerClient", {
        assigned: id,
        hasClientToken: !!clientToken,
        remoteAddr,
      });
      if (id === null) {
        ws.send(JSON.stringify({ type: "error", message: "no daemon available" }));
        ws.close();
      }
    }
  });

  return {
    start(): Promise<void> {
      return new Promise((resolve, reject) => {
        httpServer.on("error", reject);
        const onListening = () => {
          log("pairing", "self-hosted http/ws listening", { port, host });
          resolve();
        };
        if (host) {
          httpServer.listen(port, host, onListening);
        } else {
          httpServer.listen(port, onListening);
        }
      });
    },

    stop(): Promise<void> {
      return new Promise((resolve) => {
        log("pairing", "self-hosted http/ws stopping", { port });
        wss.close();
        httpServer.close(() => resolve());
      });
    },

    port,
    host,
  };
}
