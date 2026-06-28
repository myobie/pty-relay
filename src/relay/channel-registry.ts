/**
 * Per-connection registry of open channels — see
 * `docs/channel-protocol.md` § "Daemon-side architecture".
 *
 * Pure data structure: no I/O, no network, no process side effects.
 * Owned by the per-connection daemon state object; cascades `close()`
 * to every registered handler when the underlying Noise session ends.
 */

/**
 * Hard cap on simultaneously-open channels per connection. Enough for
 * "your terminal + a couple of rsync/git transfers"; small enough that a
 * buggy client can't flood the daemon. Lift later without a protocol
 * change if the cap becomes the bottleneck.
 */
export const MAX_CHANNELS = 16;

/**
 * One end of a registered channel — either a `SessionBridge` (pty) or
 * an `ExecBridge` (exec) on the daemon side, or their client-side
 * counterparts. Anything implementing this can plug into the registry.
 */
export interface ChannelHandler {
  /** Discriminator for diagnostics and per-mode invariants. */
  mode: "pty" | "exec";
  /**
   * Called for each inbound frame on this channel. `type` is the
   * frame's `type` byte (`FRAME_TYPE.DATA`, `FRAME_TYPE.SIGNAL`, …);
   * `payload` is a defensive copy and can be retained.
   */
  onFrame(type: number, payload: Uint8Array): void;
  /**
   * Tear down the channel. Implementations must be idempotent — the
   * registry may call this during cascade-close at the same time the
   * peer sends `channel_close`. `reason` is a short tag suitable for
   * logging; not user-facing.
   */
  close(reason: string): void;
}

export class ChannelOpenError extends Error {
  readonly code: "id_collision" | "channel_limit";
  constructor(code: "id_collision" | "channel_limit", message: string) {
    super(message);
    this.code = code;
    this.name = "ChannelOpenError";
  }
}

export class ChannelRegistry {
  private readonly handlers = new Map<number, ChannelHandler>();

  /**
   * Register a new channel.
   *
   * Throws `ChannelOpenError("id_collision")` if `id` is already open;
   * throws `ChannelOpenError("channel_limit")` if the registry is at
   * `MAX_CHANNELS`. Both translate to a `channel_open_error` reply at
   * the control layer.
   */
  open(id: number, handler: ChannelHandler): void {
    if (this.handlers.has(id)) {
      throw new ChannelOpenError(
        "id_collision",
        `channel id ${id} is already open`,
      );
    }
    if (this.handlers.size >= MAX_CHANNELS) {
      throw new ChannelOpenError(
        "channel_limit",
        `at MAX_CHANNELS (${MAX_CHANNELS}) — close one before opening another`,
      );
    }
    this.handlers.set(id, handler);
  }

  /**
   * Remove the handler for `id` and call its `close(reason)`. Returns
   * true if the id was present, false if not (idempotent). The handler
   * is removed *before* its close() runs so a close() that synchronously
   * calls back into the registry can't observe the half-state.
   */
  close(id: number, reason: string): boolean {
    const handler = this.handlers.get(id);
    if (!handler) return false;
    this.handlers.delete(id);
    try {
      handler.close(reason);
    } catch {
      // Handlers must not throw, but if one does we've already removed
      // it — swallowing here prevents a buggy handler from poisoning the
      // dispatcher's outer loop.
    }
    return true;
  }

  get(id: number): ChannelHandler | undefined {
    return this.handlers.get(id);
  }

  has(id: number): boolean {
    return this.handlers.has(id);
  }

  size(): number {
    return this.handlers.size;
  }

  ids(): number[] {
    return [...this.handlers.keys()];
  }

  /**
   * Cascade-close every registered channel. Called when the Noise
   * session ends for any reason (peer drop, revoke, fatal protocol
   * error). Each handler's `close(reason)` is called exactly once even
   * if it throws.
   */
  closeAll(reason: string): void {
    // Snapshot the ids so close() side effects can't perturb the
    // iteration order. `close()` removes from the map; the snapshot is
    // the authoritative list.
    const ids = [...this.handlers.keys()];
    for (const id of ids) {
      this.close(id, reason);
    }
  }
}
