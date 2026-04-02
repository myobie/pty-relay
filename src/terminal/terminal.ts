import { Buffer } from "node:buffer";
import {
  PacketReader,
  PacketTooLargeError,
  MessageType,
  encodeData,
  encodeResize,
  encodeDetach,
} from "@myobie/pty/protocol";
import type { Packet } from "@myobie/pty/protocol";
import { TERMINAL_SANITIZE } from "@myobie/pty/client";
import type { ClientRelayConnection } from "./client-connection.ts";

const CTRL_BACKSLASH = 0x1c;
// Kitty's CSI u encoding for Ctrl+\: ESC [ 92 ; 5 u
const KITTY_CTRL_BACKSLASH = Buffer.from("\x1b[92;5u");
const DOUBLE_TAP_MS = 300;

export interface TerminalOptions {
  connection: ClientRelayConnection;
  session: string;
  cols: number;
  rows: number;
  skipAttach?: boolean;
  onDetach?: () => void;
  onExit?: (code: number) => void;
  onError?: (message: string) => void;
}

/**
 * Manages the terminal I/O for the client.
 * Enters raw mode, sends keystrokes through the encrypted tunnel,
 * and renders output from the pty session.
 */
export class Terminal {
  private connection: ClientRelayConnection;
  private session: string;
  private packetReader = new PacketReader();
  private lastCtrlBackslash = 0;
  private attached = false;
  private skipAttach: boolean;
  private options: TerminalOptions;
  private stdinHandler: ((data: Buffer | string) => void) | null = null;
  private resizeHandler: (() => void) | null = null;

  constructor(options: TerminalOptions) {
    this.connection = options.connection;
    this.session = options.session;
    this.skipAttach = options.skipAttach || false;
    this.options = options;
  }

  /**
   * Send the attach request to the daemon and start bridging terminal I/O.
   */
  async start(cols: number, rows: number): Promise<void> {
    if (!this.skipAttach) {
      // Send attach request (JSON, inside the encrypted tunnel)
      const attachMsg = JSON.stringify({
        type: "attach",
        session: this.session,
        cols,
        rows,
      });
      this.connection.send(new TextEncoder().encode(attachMsg));
    }
    // If skipAttach, the spawn message was already sent by connect.ts
    // Wait for "spawned" then "attached" responses in handleMessage
  }

  /**
   * Handle a decrypted message from the daemon.
   * After the initial "attached" response, all messages are raw pty protocol packets.
   */
  handleMessage(data: Uint8Array): void {
    if (!this.attached) {
      try {
        const msg = JSON.parse(new TextDecoder().decode(data));
        if (msg.type === "spawned") {
          // Daemon created the session — it will auto-attach, wait for "attached"
          return;
        } else if (msg.type === "attached") {
          this.attached = true;
          this.enterRawMode();
          return;
        } else if (msg.type === "error") {
          if (this.options.onError) {
            this.cleanup();
            this.options.onError(msg.message);
            return;
          }
          console.error(`Error: ${msg.message}`);
          this.cleanup();
          process.exit(1);
          return;
        }
      } catch {
        // Not JSON — might be raw pty data if attach was already processed
      }
    }

    // Raw pty protocol packets. A malicious or malfunctioning peer can declare
    // an oversized length header (>32 MiB) to try to exhaust memory on the
    // receiver; PacketReader throws PacketTooLargeError in that case. Tear down
    // the connection cleanly instead of propagating.
    let packets: Packet[];
    try {
      packets = this.packetReader.feed(Buffer.from(data));
    } catch (err) {
      if (err instanceof PacketTooLargeError) {
        const msg = `peer sent oversized packet (${err.message})`;
        if (this.options.onError) {
          this.cleanup();
          this.options.onError(msg);
          return;
        }
        console.error(`Error: ${msg}`);
        this.cleanup();
        process.exit(1);
      }
      throw err;
    }
    for (const packet of packets) {
      this.handlePacket(packet);
    }
  }

  private handlePacket(packet: Packet): void {
    switch (packet.type) {
      case MessageType.DATA:
        process.stdout.write(packet.payload);
        break;

      case MessageType.SCREEN:
        // Clear screen and write the full screen state
        process.stdout.write("\x1b[2J\x1b[H");
        process.stdout.write(packet.payload);
        break;

      case MessageType.EXIT: {
        const exitCode = packet.payload.length >= 4
          ? packet.payload.readInt32BE(0)
          : -1;
        this.cleanup();
        if (this.options.onExit) {
          this.options.onExit(exitCode);
          return;
        }
        process.exit(exitCode === 0 ? 0 : 1);
        break;
      }
    }
  }

  private enterRawMode(): void {
    if (!process.stdin.isTTY) {
      console.error("stdin is not a TTY");
      return;
    }

    // Remove old listeners to avoid double-firing. Keep encoding as
    // utf8 — we convert strings to Buffers in handleStdin. This avoids
    // flipping encoding between null/utf8 which corrupts Node's internal
    // stream decoder and makes arrow keys output garbage (^[[A) when
    // the TUI resumes after detach.
    process.stdin.removeAllListeners("data");
    process.stdin.setEncoding("utf8");
    process.stdin.setRawMode(true);
    process.stdin.resume();

    this.stdinHandler = (data: Buffer | string) => {
      this.handleStdin(data);
    };
    process.stdin.on("data", this.stdinHandler);

    // Handle terminal resize
    this.resizeHandler = () => {
      if (!process.stdout.columns || !process.stdout.rows) return;
      const resizeData = encodeResize(process.stdout.rows, process.stdout.columns);
      try {
        this.connection.send(resizeData);
      } catch {}
    };
    process.stdout.on("resize", this.resizeHandler);
  }

  /**
   * Remove stdin data and stdout resize listeners to prevent leaks.
   */
  removeListeners(): void {
    if (this.stdinHandler) {
      process.stdin.removeListener("data", this.stdinHandler);
      this.stdinHandler = null;
    }
    if (this.resizeHandler) {
      process.stdout.removeListener("resize", this.resizeHandler);
      this.resizeHandler = null;
    }
  }

  private handleStdin(data: Buffer | string): void {
    // Ensure we have a Buffer — stdin may deliver a string if encoding
    // was set to utf8 by a prior prompt (passphrase, session picker, etc.)
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);

    // Check for Ctrl+\ (detach key) — raw byte or Kitty CSI u encoding
    const isCtrlBackslash = (buf.length === 1 && buf[0] === CTRL_BACKSLASH)
      || buf.equals(KITTY_CTRL_BACKSLASH);
    if (isCtrlBackslash) {
      const now = Date.now();
      if (now - this.lastCtrlBackslash < DOUBLE_TAP_MS) {
        // Double tap — pass through to remote
        this.lastCtrlBackslash = 0;
        this.sendData(buf);
        return;
      }
      this.lastCtrlBackslash = now;
      // Single press — detach
      this.detach();
      return;
    }

    this.lastCtrlBackslash = 0;
    this.sendData(buf);
  }

  private sendData(data: Buffer): void {
    const encoded = encodeData(data.toString());
    try {
      this.connection.send(encoded);
    } catch {}
  }

  private detach(): void {
    try {
      this.connection.send(encodeDetach());
    } catch {}
    this.cleanup();
    process.stdout.write("\r\n[detached]\r\n");
    if (this.options.onDetach) {
      this.options.onDetach();
      return;
    }
    process.exit(0);
  }

  cleanup(): void {
    this.removeListeners();
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(false);
    }
    process.stdin.pause();
    // Reset terminal modes, move cursor to bottom of screen
    process.stdout.write(TERMINAL_SANITIZE + "\x1b[999;1H");
  }
}
