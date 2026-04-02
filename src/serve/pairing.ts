import { randomBytes } from "node:crypto";
import type WebSocket from "ws";

export interface ClientEntry {
  client: WebSocket;
  daemon: WebSocket | null; // per-client daemon socket, null while waiting
}

interface PrimaryEntry {
  primary: WebSocket; // daemon's control socket
  clients: Map<string, ClientEntry>; // keyed by client_id
  label: string | null; // daemon label from query params
}

/**
 * In-memory pairing registry for the self-hosted relay.
 * Supports N concurrent clients per daemon:
 * - One primary daemon WebSocket per secret_hash (control channel)
 * - Each client gets a unique client_id
 * - Daemon opens a per-client WebSocket to pair with each client
 * - Binary frames are forwarded between each client and its paired daemon socket
 */
export class PairingRegistry {
  private entries = new Map<string, PrimaryEntry>();

  /**
   * Register the primary daemon control WebSocket.
   * Returns false if a primary daemon is already registered for this secret_hash.
   */
  registerDaemon(secretHash: string, ws: WebSocket, label?: string | null): boolean {
    const existing = this.entries.get(secretHash);
    if (existing) return false; // primary already exists

    const entry: PrimaryEntry = {
      primary: ws,
      clients: new Map(),
      label: label ?? null,
    };

    this.entries.set(secretHash, entry);

    // Handle text messages from primary daemon (e.g., reject_client)
    ws.on("message", (data: Buffer | string, isBinary: boolean) => {
      if (isBinary) return; // only handle text frames
      const text = typeof data === "string" ? data : data.toString("utf-8");
      try {
        const msg = JSON.parse(text);
        if (msg.type === "reject_client" && msg.client_id && msg.reason) {
          const clientEntry = entry.clients.get(msg.client_id);
          if (clientEntry) {
            try {
              clientEntry.client.send(JSON.stringify({ type: "error", message: msg.reason }));
            } catch {
              // ignore send errors
            }
            clientEntry.client.close();
            entry.clients.delete(msg.client_id);
          }
        } else if (msg.type === "hold_client" && msg.client_id) {
          const clientEntry = entry.clients.get(msg.client_id);
          if (clientEntry) {
            try {
              clientEntry.client.send(JSON.stringify({ type: "waiting_for_approval" }));
            } catch {
              // ignore send errors
            }
          }
        }
      } catch {
        // ignore unparseable text
      }
    });

    // When primary daemon closes, tear down everything
    ws.on("close", () => {
      const current = this.entries.get(secretHash);
      if (!current || current.primary !== ws) return;

      // Notify and close all clients
      for (const [, clientEntry] of current.clients) {
        try {
          clientEntry.client.send(JSON.stringify({ type: "peer_disconnected" }));
        } catch {
          // ignore send errors on closing sockets
        }
        clientEntry.client.close();

        // Also close per-client daemon sockets
        if (clientEntry.daemon) {
          clientEntry.daemon.close();
        }
      }

      this.entries.delete(secretHash);
    });

    return true;
  }

  /**
   * Register a new client. Generates a random client_id, notifies the primary
   * daemon via a client_waiting message.
   * Returns the client_id, or null if no primary daemon exists.
   */
  registerClient(
    secretHash: string,
    ws: WebSocket,
    clientToken?: string,
    meta?: {
      remoteAddr?: string | null;
      userAgent?: string | null;
      origin?: string | null;
    }
  ): string | null {
    const entry = this.entries.get(secretHash);
    if (!entry) return null; // no primary daemon

    const clientId = randomBytes(4).toString("hex"); // 8-char hex

    const clientEntry: ClientEntry = {
      client: ws,
      daemon: null,
    };

    entry.clients.set(clientId, clientEntry);

    // Notify the primary daemon that a client is waiting
    try {
      const msg: Record<string, unknown> = {
        type: "client_waiting",
        client_id: clientId,
      };
      if (clientToken) {
        msg.client_token = clientToken;
      }
      if (meta && (meta.remoteAddr || meta.userAgent || meta.origin)) {
        msg.meta = {
          remote_addr: meta.remoteAddr ?? null,
          user_agent: meta.userAgent ?? null,
          origin: meta.origin ?? null,
        };
      }
      entry.primary.send(JSON.stringify(msg));
    } catch {
      // primary might be closing
    }

    // When client closes: clean up and notify
    ws.on("close", () => {
      const current = this.entries.get(secretHash);
      if (!current) return;

      const ce = current.clients.get(clientId);
      if (!ce || ce.client !== ws) return;

      // Notify paired per-client daemon if any
      if (ce.daemon) {
        try {
          ce.daemon.send(JSON.stringify({ type: "peer_disconnected" }));
        } catch {
          // ignore
        }
        ce.daemon.close();
      }

      current.clients.delete(clientId);

      // Notify primary daemon that this client disconnected
      try {
        current.primary.send(
          JSON.stringify({ type: "client_disconnected", client_id: clientId })
        );
      } catch {
        // ignore
      }
    });

    return clientId;
  }

  /**
   * Register a per-client daemon WebSocket. This pairs it with the waiting client.
   * Returns false if the client is not found.
   */
  registerDaemonForClient(
    secretHash: string,
    clientId: string,
    ws: WebSocket
  ): boolean {
    const entry = this.entries.get(secretHash);
    if (!entry) return false;

    const clientEntry = entry.clients.get(clientId);
    if (!clientEntry) return false;

    clientEntry.daemon = ws;

    // Send paired to both sides
    const paired = JSON.stringify({ type: "paired" });
    try {
      clientEntry.client.send(paired);
    } catch {
      // ignore
    }
    try {
      ws.send(paired);
    } catch {
      // ignore
    }

    // Set up binary forwarding between the per-client daemon and the client
    const client = clientEntry.client;
    const daemon = ws;

    daemon.on("message", (data, isBinary) => {
      if (isBinary) { try { if (client.readyState === 1) client.send(data); } catch {} }
    });

    client.on("message", (data, isBinary) => {
      if (isBinary) { try { if (daemon.readyState === 1) daemon.send(data); } catch {} }
    });

    // When per-client daemon closes: notify its paired client, remove daemon ref
    ws.on("close", () => {
      const current = this.entries.get(secretHash);
      if (!current) return;

      const ce = current.clients.get(clientId);
      if (!ce || ce.daemon !== ws) return;

      try {
        ce.client.send(JSON.stringify({ type: "peer_disconnected" }));
      } catch {
        // ignore
      }

      ce.daemon = null;
    });

    return true;
  }
}
