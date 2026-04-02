import { describe, it, expect, vi, beforeEach } from "vitest";
import { PairingRegistry } from "./pairing.ts";

/** Create a mock WebSocket with enough fidelity for registry tests. */
function createMockWs() {
  const listeners = new Map<string, Set<(...args: any[]) => void>>();
  const sent: any[] = [];
  let readyState = 1; // OPEN

  const ws = {
    readyState,
    send: vi.fn((data: any) => {
      sent.push(data);
    }),
    close: vi.fn(() => {
      ws.readyState = 3; // CLOSED
    }),
    on: vi.fn((event: string, handler: (...args: any[]) => void) => {
      if (!listeners.has(event)) listeners.set(event, new Set());
      listeners.get(event)!.add(handler);
    }),
    // Test helper: emit an event on this mock
    _emit(event: string, ...args: any[]) {
      const handlers = listeners.get(event);
      if (handlers) {
        for (const h of handlers) h(...args);
      }
    },
    // Test helper: get sent messages
    _sent: sent,
  };

  return ws as any;
}

/** Parse all JSON text messages sent on a mock WebSocket. */
function sentMessages(ws: any): any[] {
  return ws._sent
    .filter((d: any) => typeof d === "string")
    .map((d: string) => JSON.parse(d));
}

describe("PairingRegistry", () => {
  let registry: PairingRegistry;

  beforeEach(() => {
    registry = new PairingRegistry();
  });

  const SECRET = "a".repeat(64);
  const SECRET2 = "b".repeat(64);

  describe("registerDaemon (primary)", () => {
    it("registers a primary daemon", () => {
      const ws = createMockWs();
      expect(registry.registerDaemon(SECRET, ws)).toBe(true);
    });

    it("rejects a second primary for the same secret_hash", () => {
      const ws1 = createMockWs();
      const ws2 = createMockWs();
      registry.registerDaemon(SECRET, ws1);
      expect(registry.registerDaemon(SECRET, ws2)).toBe(false);
    });

    it("allows primary daemons for different secret_hashes", () => {
      const ws1 = createMockWs();
      const ws2 = createMockWs();
      expect(registry.registerDaemon(SECRET, ws1)).toBe(true);
      expect(registry.registerDaemon(SECRET2, ws2)).toBe(true);
    });
  });

  describe("registerClient", () => {
    it("returns null if no primary daemon exists", () => {
      const ws = createMockWs();
      expect(registry.registerClient(SECRET, ws)).toBeNull();
    });

    it("returns a client_id when primary daemon exists", () => {
      const daemon = createMockWs();
      registry.registerDaemon(SECRET, daemon);

      const client = createMockWs();
      const clientId = registry.registerClient(SECRET, client);
      expect(clientId).toBeTruthy();
      expect(typeof clientId).toBe("string");
      expect(clientId!.length).toBe(8); // 4 bytes = 8 hex chars
    });

    it("sends client_waiting to primary daemon", () => {
      const daemon = createMockWs();
      registry.registerDaemon(SECRET, daemon);

      const client = createMockWs();
      const clientId = registry.registerClient(SECRET, client);

      const messages = sentMessages(daemon);
      expect(messages).toContainEqual({
        type: "client_waiting",
        client_id: clientId,
      });
    });

    it("supports multiple clients with unique client_ids", () => {
      const daemon = createMockWs();
      registry.registerDaemon(SECRET, daemon);

      const client1 = createMockWs();
      const client2 = createMockWs();
      const id1 = registry.registerClient(SECRET, client1);
      const id2 = registry.registerClient(SECRET, client2);

      expect(id1).toBeTruthy();
      expect(id2).toBeTruthy();
      expect(id1).not.toBe(id2);
    });
  });

  describe("registerDaemonForClient", () => {
    it("returns false if no primary entry exists", () => {
      const ws = createMockWs();
      expect(registry.registerDaemonForClient(SECRET, "abc", ws)).toBe(false);
    });

    it("returns false if client_id not found", () => {
      const daemon = createMockWs();
      registry.registerDaemon(SECRET, daemon);

      const ws = createMockWs();
      expect(registry.registerDaemonForClient(SECRET, "nonexistent", ws)).toBe(
        false
      );
    });

    it("pairs per-client daemon with waiting client", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const client = createMockWs();
      const clientId = registry.registerClient(SECRET, client)!;

      const perClientDaemon = createMockWs();
      const ok = registry.registerDaemonForClient(
        SECRET,
        clientId,
        perClientDaemon
      );
      expect(ok).toBe(true);

      // Both should receive "paired"
      expect(sentMessages(client)).toContainEqual({ type: "paired" });
      expect(sentMessages(perClientDaemon)).toContainEqual({ type: "paired" });
    });

    it("forwards binary data between paired client and per-client daemon", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const client = createMockWs();
      const clientId = registry.registerClient(SECRET, client)!;

      const perClientDaemon = createMockWs();
      registry.registerDaemonForClient(SECRET, clientId, perClientDaemon);

      // Simulate binary from daemon -> client
      const binaryData = Buffer.from([1, 2, 3]);
      perClientDaemon._emit("message", binaryData, true);
      expect(client.send).toHaveBeenCalledWith(binaryData);

      // Simulate binary from client -> daemon
      const binaryData2 = Buffer.from([4, 5, 6]);
      client._emit("message", binaryData2, true);
      expect(perClientDaemon.send).toHaveBeenCalledWith(binaryData2);
    });
  });

  describe("two independent clients", () => {
    it("connect and pair independently", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const client1 = createMockWs();
      const client2 = createMockWs();
      const id1 = registry.registerClient(SECRET, client1)!;
      const id2 = registry.registerClient(SECRET, client2)!;

      const daemon1 = createMockWs();
      const daemon2 = createMockWs();
      expect(registry.registerDaemonForClient(SECRET, id1, daemon1)).toBe(true);
      expect(registry.registerDaemonForClient(SECRET, id2, daemon2)).toBe(true);

      // Both clients and daemons receive paired
      expect(sentMessages(client1)).toContainEqual({ type: "paired" });
      expect(sentMessages(client2)).toContainEqual({ type: "paired" });
      expect(sentMessages(daemon1)).toContainEqual({ type: "paired" });
      expect(sentMessages(daemon2)).toContainEqual({ type: "paired" });

      // Binary forwarding is isolated: daemon1 <-> client1 only
      const data1 = Buffer.from([10]);
      daemon1._emit("message", data1, true);
      expect(client1.send).toHaveBeenCalledWith(data1);
      // client2 should NOT receive it (only "paired" text was sent)
      const client2BinaryCalls = client2.send.mock.calls.filter(
        (call: any[]) => Buffer.isBuffer(call[0])
      );
      expect(client2BinaryCalls).toHaveLength(0);
    });
  });

  describe("client disconnect", () => {
    it("only affects its paired daemon, not others", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const client1 = createMockWs();
      const client2 = createMockWs();
      const id1 = registry.registerClient(SECRET, client1)!;
      const id2 = registry.registerClient(SECRET, client2)!;

      const daemon1 = createMockWs();
      const daemon2 = createMockWs();
      registry.registerDaemonForClient(SECRET, id1, daemon1);
      registry.registerDaemonForClient(SECRET, id2, daemon2);

      // Client 1 disconnects
      client1._emit("close");

      // Daemon 1 should get peer_disconnected and be closed
      expect(sentMessages(daemon1)).toContainEqual({
        type: "peer_disconnected",
      });
      expect(daemon1.close).toHaveBeenCalled();

      // Primary should get client_disconnected for client 1
      expect(sentMessages(primary)).toContainEqual({
        type: "client_disconnected",
        client_id: id1,
      });

      // Daemon 2 and client 2 should be unaffected (no peer_disconnected)
      const daemon2PeerDisconnects = sentMessages(daemon2).filter(
        (m) => m.type === "peer_disconnected"
      );
      expect(daemon2PeerDisconnects).toHaveLength(0);
    });

    it("sends client_disconnected to primary when unpaired client disconnects", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const client = createMockWs();
      const clientId = registry.registerClient(SECRET, client)!;

      // Client disconnects before being paired
      client._emit("close");

      expect(sentMessages(primary)).toContainEqual({
        type: "client_disconnected",
        client_id: clientId,
      });
    });
  });

  describe("primary daemon disconnect", () => {
    it("closes all clients and per-client daemons", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const client1 = createMockWs();
      const client2 = createMockWs();
      const id1 = registry.registerClient(SECRET, client1)!;
      const id2 = registry.registerClient(SECRET, client2)!;

      const daemon1 = createMockWs();
      const daemon2 = createMockWs();
      registry.registerDaemonForClient(SECRET, id1, daemon1);
      registry.registerDaemonForClient(SECRET, id2, daemon2);

      // Primary daemon disconnects
      primary._emit("close");

      // All clients should get peer_disconnected and be closed
      expect(sentMessages(client1)).toContainEqual({
        type: "peer_disconnected",
      });
      expect(client1.close).toHaveBeenCalled();

      expect(sentMessages(client2)).toContainEqual({
        type: "peer_disconnected",
      });
      expect(client2.close).toHaveBeenCalled();

      // Per-client daemons should be closed
      expect(daemon1.close).toHaveBeenCalled();
      expect(daemon2.close).toHaveBeenCalled();

      // New registrations should work (entry was removed)
      const newPrimary = createMockWs();
      expect(registry.registerDaemon(SECRET, newPrimary)).toBe(true);
    });
  });

  describe("client rejection", () => {
    it("primary daemon can reject a waiting client via reject_client text message", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const client = createMockWs();
      const clientId = registry.registerClient(SECRET, client)!;

      // Primary daemon sends reject_client text message
      const rejectMsg = JSON.stringify({
        type: "reject_client",
        client_id: clientId,
        reason: "max clients reached",
      });
      primary._emit("message", rejectMsg, false);

      // Client should receive error message
      expect(sentMessages(client)).toContainEqual({
        type: "error",
        message: "max clients reached",
      });

      // Client should be closed
      expect(client.close).toHaveBeenCalled();
    });

    it("reject_client with unknown client_id is a no-op", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      // Send reject for a client that doesn't exist — should not throw
      const rejectMsg = JSON.stringify({
        type: "reject_client",
        client_id: "nonexistent",
        reason: "max clients reached",
      });
      primary._emit("message", rejectMsg, false);
    });

    it("rejected client is removed from the clients map", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const client = createMockWs();
      const clientId = registry.registerClient(SECRET, client)!;

      // Reject the client
      const rejectMsg = JSON.stringify({
        type: "reject_client",
        client_id: clientId,
        reason: "max clients reached",
      });
      primary._emit("message", rejectMsg, false);

      // Trying to register a per-client daemon for that client should fail
      const daemon = createMockWs();
      expect(registry.registerDaemonForClient(SECRET, clientId, daemon)).toBe(false);
    });
  });

  describe("client_token forwarding", () => {
    it("includes client_token in client_waiting when provided", () => {
      const daemon = createMockWs();
      registry.registerDaemon(SECRET, daemon);

      const client = createMockWs();
      const clientId = registry.registerClient(SECRET, client, "mytoken123");

      const messages = sentMessages(daemon);
      expect(messages).toContainEqual({
        type: "client_waiting",
        client_id: clientId,
        client_token: "mytoken123",
      });
    });

    it("omits client_token in client_waiting when not provided", () => {
      const daemon = createMockWs();
      registry.registerDaemon(SECRET, daemon);

      const client = createMockWs();
      const clientId = registry.registerClient(SECRET, client);

      const messages = sentMessages(daemon);
      const waiting = messages.find((m) => m.type === "client_waiting");
      expect(waiting).toBeDefined();
      expect(waiting.client_token).toBeUndefined();
    });
  });

  describe("hold_client", () => {
    it("sends waiting_for_approval to the client", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const client = createMockWs();
      const clientId = registry.registerClient(SECRET, client)!;

      // Primary daemon sends hold_client
      const holdMsg = JSON.stringify({
        type: "hold_client",
        client_id: clientId,
      });
      primary._emit("message", holdMsg, false);

      expect(sentMessages(client)).toContainEqual({
        type: "waiting_for_approval",
      });
    });

    it("hold_client with unknown client_id is a no-op", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const holdMsg = JSON.stringify({
        type: "hold_client",
        client_id: "nonexistent",
      });
      // Should not throw
      primary._emit("message", holdMsg, false);
    });
  });

  describe("per-client daemon disconnect", () => {
    it("only affects its paired client", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const client1 = createMockWs();
      const client2 = createMockWs();
      const id1 = registry.registerClient(SECRET, client1)!;
      const id2 = registry.registerClient(SECRET, client2)!;

      const daemon1 = createMockWs();
      const daemon2 = createMockWs();
      registry.registerDaemonForClient(SECRET, id1, daemon1);
      registry.registerDaemonForClient(SECRET, id2, daemon2);

      // Per-client daemon 1 disconnects
      daemon1._emit("close");

      // Client 1 should get peer_disconnected
      expect(sentMessages(client1)).toContainEqual({
        type: "peer_disconnected",
      });

      // Client 2 should be unaffected
      const client2PeerDisconnects = sentMessages(client2).filter(
        (m) => m.type === "peer_disconnected"
      );
      expect(client2PeerDisconnects).toHaveLength(0);

      // Client 2 and daemon 2 should still be able to communicate
      const data = Buffer.from([99]);
      daemon2._emit("message", data, true);
      expect(client2.send).toHaveBeenCalledWith(data);
    });

    it("does not close the client socket", () => {
      const primary = createMockWs();
      registry.registerDaemon(SECRET, primary);

      const client = createMockWs();
      const clientId = registry.registerClient(SECRET, client)!;

      const daemon = createMockWs();
      registry.registerDaemonForClient(SECRET, clientId, daemon);

      daemon._emit("close");

      // Client gets notified but is NOT closed (daemon might reconnect)
      expect(sentMessages(client)).toContainEqual({
        type: "peer_disconnected",
      });
      expect(client.close).not.toHaveBeenCalled();
    });
  });
});
