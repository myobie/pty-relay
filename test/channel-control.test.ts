import { describe, it, expect } from "vitest";
import {
  parseControlMessage,
  encodeControlMessage,
  PROTOCOL_VERSION,
  type ControlMessage,
} from "../src/relay/channel-control.ts";

function bytesFromJson(obj: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(obj));
}

describe("parseControlMessage — channel_open (pty)", () => {
  it("parses a minimal pty channel_open", () => {
    const r = parseControlMessage(
      bytesFromJson({ type: "channel_open", id: 1, mode: "pty", session: "demo" })
    );
    expect(r.ok).toBe(true);
    if (!r.ok || r.kind !== "control") return;
    expect(r.msg).toMatchObject({
      type: "channel_open",
      id: 1,
      mode: "pty",
      session: "demo",
    });
  });

  it("includes cols/rows when provided", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_open",
        id: 1,
        mode: "pty",
        session: "demo",
        cols: 80,
        rows: 24,
      })
    );
    expect(r.ok).toBe(true);
    if (!r.ok || r.kind !== "control" || r.msg.type !== "channel_open" || r.msg.mode !== "pty") return;
    expect(r.msg.cols).toBe(80);
    expect(r.msg.rows).toBe(24);
  });

  it("rejects pty channel_open with missing session", () => {
    const r = parseControlMessage(
      bytesFromJson({ type: "channel_open", id: 1, mode: "pty" })
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe("control_frame_shape");
  });

  it("rejects pty channel_open with empty session string", () => {
    const r = parseControlMessage(
      bytesFromJson({ type: "channel_open", id: 1, mode: "pty", session: "" })
    );
    expect(r.ok).toBe(false);
  });
});

describe("parseControlMessage — channel_open (exec)", () => {
  it("parses a minimal exec channel_open", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_open",
        id: 2,
        mode: "exec",
        argv: ["rsync", "--server"],
      })
    );
    expect(r.ok).toBe(true);
    if (!r.ok || r.kind !== "control" || r.msg.type !== "channel_open" || r.msg.mode !== "exec") return;
    expect(r.msg.argv).toEqual(["rsync", "--server"]);
    expect(r.msg.env).toBeUndefined();
    expect(r.msg.cwd).toBeUndefined();
  });

  it("parses exec channel_open with env + cwd", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_open",
        id: 2,
        mode: "exec",
        argv: ["git"],
        env: { PATH: "/usr/bin" },
        cwd: "/tmp",
      })
    );
    expect(r.ok).toBe(true);
    if (!r.ok || r.kind !== "control" || r.msg.type !== "channel_open" || r.msg.mode !== "exec") return;
    expect(r.msg.env).toEqual({ PATH: "/usr/bin" });
    expect(r.msg.cwd).toBe("/tmp");
  });

  it("accepts explicit null env/cwd", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_open",
        id: 2,
        mode: "exec",
        argv: ["rsync"],
        env: null,
        cwd: null,
      })
    );
    expect(r.ok).toBe(true);
    if (!r.ok || r.kind !== "control" || r.msg.type !== "channel_open" || r.msg.mode !== "exec") return;
    expect(r.msg.env).toBeNull();
    expect(r.msg.cwd).toBeNull();
  });

  it("rejects exec channel_open with empty argv", () => {
    const r = parseControlMessage(
      bytesFromJson({ type: "channel_open", id: 2, mode: "exec", argv: [] })
    );
    expect(r.ok).toBe(false);
  });

  it("rejects exec channel_open with non-string argv element", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_open",
        id: 2,
        mode: "exec",
        argv: ["rsync", 42],
      })
    );
    expect(r.ok).toBe(false);
  });

  it("rejects exec channel_open with non-string env value", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_open",
        id: 2,
        mode: "exec",
        argv: ["rsync"],
        env: { PATH: 1 },
      })
    );
    expect(r.ok).toBe(false);
  });
});

describe("parseControlMessage — channel_open_ack / error", () => {
  it("parses channel_open_ack", () => {
    const r = parseControlMessage(
      bytesFromJson({ type: "channel_open_ack", id: 7 })
    );
    expect(r.ok).toBe(true);
    if (!r.ok || r.kind !== "control") return;
    expect(r.msg).toEqual({ type: "channel_open_ack", id: 7 });
  });

  it("parses channel_open_error for every code", () => {
    const codes = [
      "mode_not_enabled",
      "argv_not_allowed",
      "session_not_found",
      "spawn_failed",
      "id_collision",
      "channel_limit",
    ] as const;
    for (const code of codes) {
      const r = parseControlMessage(
        bytesFromJson({
          type: "channel_open_error",
          id: 1,
          code,
          message: `human ${code}`,
        })
      );
      expect(r.ok, `failed for ${code}`).toBe(true);
      if (!r.ok || r.kind !== "control" || r.msg.type !== "channel_open_error") return;
      expect(r.msg.code).toBe(code);
    }
  });

  it("rejects unknown channel_open_error code", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_open_error",
        id: 1,
        code: "made_up_code",
        message: "nope",
      })
    );
    expect(r.ok).toBe(false);
  });
});

describe("parseControlMessage — channel_close / channel_exit", () => {
  it("parses channel_close for every reason", () => {
    const reasons = [
      "client_detach",
      "operator_close",
      "peer_lost",
      "protocol_error",
      "exit",
    ] as const;
    for (const reason of reasons) {
      const r = parseControlMessage(
        bytesFromJson({ type: "channel_close", id: 1, reason })
      );
      expect(r.ok, `failed for ${reason}`).toBe(true);
    }
  });

  it("parses channel_exit with exit_code", () => {
    const r = parseControlMessage(
      bytesFromJson({ type: "channel_exit", id: 1, exit_code: 0, signal: null })
    );
    expect(r.ok).toBe(true);
    if (!r.ok || r.kind !== "control" || r.msg.type !== "channel_exit") return;
    expect(r.msg.exit_code).toBe(0);
    expect(r.msg.signal).toBeNull();
  });

  it("parses channel_exit with signal", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_exit",
        id: 1,
        exit_code: null,
        signal: "SIGTERM",
      })
    );
    expect(r.ok).toBe(true);
    if (!r.ok || r.kind !== "control" || r.msg.type !== "channel_exit") return;
    expect(r.msg.exit_code).toBeNull();
    expect(r.msg.signal).toBe("SIGTERM");
  });

  it("rejects channel_exit with both exit_code AND signal set", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_exit",
        id: 1,
        exit_code: 0,
        signal: "SIGTERM",
      })
    );
    expect(r.ok).toBe(false);
  });

  it("rejects channel_exit with neither exit_code NOR signal", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_exit",
        id: 1,
        exit_code: null,
        signal: null,
      })
    );
    expect(r.ok).toBe(false);
  });
});

describe("parseControlMessage — keepalive / error / unknown", () => {
  it("parses keepalive", () => {
    const r = parseControlMessage(bytesFromJson({ type: "keepalive" }));
    expect(r.ok).toBe(true);
    if (!r.ok || r.kind !== "control") return;
    expect(r.msg).toEqual({ type: "keepalive" });
  });

  it("routes `error` through onAppMessage (the v1 RPC vocabulary uses {type:'error',message} without a code field)", () => {
    const r = parseControlMessage(
      bytesFromJson({ type: "error", message: "session not found" }),
    );
    expect(r.ok).toBe(true);
    if (!r.ok || r.kind !== "app") return;
    expect(r.type).toBe("error");
    expect(r.json).toEqual({ type: "error", message: "session not found" });
  });

  it("returns an `app` envelope for unrecognized types (v1 session RPC passthrough)", () => {
    const r = parseControlMessage(
      bytesFromJson({ type: "from_the_future", id: 1, foo: "bar" }),
    );
    expect(r.ok).toBe(true);
    if (!r.ok || r.kind !== "app") return;
    expect(r.type).toBe("from_the_future");
    expect(r.json).toEqual({ type: "from_the_future", id: 1, foo: "bar" });
  });
});

describe("parseControlMessage — frame-level failures", () => {
  it("rejects non-UTF8 bytes", () => {
    const bytes = new Uint8Array([0xff, 0xfe, 0xfd]);
    const r = parseControlMessage(bytes);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe("control_frame_decode");
  });

  it("rejects malformed JSON", () => {
    const r = parseControlMessage(new TextEncoder().encode("{not-json"));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe("control_frame_json");
  });

  it("rejects a JSON array (not an object)", () => {
    const r = parseControlMessage(bytesFromJson([1, 2, 3]));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe("control_frame_shape");
  });

  it("rejects a JSON object without a string `type` field", () => {
    const r = parseControlMessage(bytesFromJson({ msg: "hello" }));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.code).toBe("control_frame_shape");
  });

  it("rejects channel_open with id 0 (reserved for control)", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_open",
        id: 0,
        mode: "pty",
        session: "demo",
      })
    );
    expect(r.ok).toBe(false);
  });

  it("rejects channel_open with a non-integer id", () => {
    const r = parseControlMessage(
      bytesFromJson({
        type: "channel_open",
        id: 1.5,
        mode: "pty",
        session: "demo",
      })
    );
    expect(r.ok).toBe(false);
  });
});

describe("encodeControlMessage round-trip", () => {
  it("round-trips every defined message shape through parseControlMessage", () => {
    const cases: ControlMessage[] = [
      {
        type: "channel_open",
        id: 1,
        mode: "pty",
        session: "demo",
        cols: 80,
        rows: 24,
      },
      {
        type: "channel_open",
        id: 2,
        mode: "exec",
        argv: ["rsync", "--server"],
        env: { PATH: "/usr/bin" },
        cwd: "/tmp",
      },
      { type: "channel_open_ack", id: 3 },
      {
        type: "channel_open_error",
        id: 4,
        code: "argv_not_allowed",
        message: "rsync only",
      },
      { type: "channel_close", id: 5, reason: "peer_lost" },
      { type: "channel_exit", id: 6, exit_code: 0, signal: null },
      { type: "channel_exit", id: 7, exit_code: null, signal: "SIGTERM" },
      { type: "keepalive" },
    ];
    for (const msg of cases) {
      const bytes = encodeControlMessage(msg);
      const parsed = parseControlMessage(bytes);
      expect(parsed.ok, `round-trip failed for ${msg.type}`).toBe(true);
      if (!parsed.ok || parsed.kind !== "control") continue;
      expect(parsed.msg).toEqual(msg);
    }
  });
});

describe("PROTOCOL_VERSION", () => {
  it("is 2", () => {
    expect(PROTOCOL_VERSION).toBe(2);
  });
});
