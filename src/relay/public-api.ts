import {
  createAuthParams,
  canonicalQuery,
  sha256Hex,
} from "../crypto/signing.ts";
import { log, now, sinceMs, redactAuthQuery } from "../log.ts";

/**
 * Typed HTTP client for the Elixir public relay (`relay.pty.computer`,
 * or `http://localhost:4000` in development).
 *
 * Signed requests fold the Ed25519 `{public_key, payload, sig}` triple
 * into the URL query string uniformly (POST + GET + WS); the signature
 * binds to METHOD + PATH + body/query hash. See src/crypto/signing.ts
 * for the canonical payload shape.
 */

export interface SigningKeys {
  public: Uint8Array;
  secret: Uint8Array;
}

export interface RequestOptions {
  /** When set, fold Ed25519 auth params into the body (POST) or query (GET). */
  signWith?: SigningKeys;
  /** Fetch timeout in milliseconds. Defaults to 15s. Most endpoints respond
   *  in tens of milliseconds; the signup email verification path is the only
   *  one that may legitimately take longer (handled via its own polling). */
  timeoutMs?: number;
  /** Additional query string params for GET calls. */
  query?: Record<string, string | number | undefined>;
}

export class PublicApiError extends Error {
  readonly status: number;
  readonly body: unknown;
  /** True when this error came from an AbortController-triggered
   *  timeout (the retry loop uses this to skip re-attempt — a timeout
   *  already spent the full timeoutMs budget). */
  readonly timedOut: boolean;
  constructor(
    status: number,
    message: string,
    body: unknown,
    timedOut = false
  ) {
    super(message);
    this.name = "PublicApiError";
    this.status = status;
    this.body = body;
    this.timedOut = timedOut;
  }
}

/** Parsed `error` field from the relay, or the best-effort fallback message. */
function extractErrorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object") {
    const msg = (body as Record<string, unknown>).error;
    if (typeof msg === "string" && msg.length > 0) return msg;
  }
  return fallback;
}

async function safeJson(res: Response): Promise<unknown> {
  const text = await res.text();
  if (text.length === 0) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function buildQuery(query: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined) continue;
    params.set(k, String(v));
  }
  const s = params.toString();
  return s.length === 0 ? "" : `?${s}`;
}

export class PublicApi {
  readonly relayUrl: string;
  constructor(relayUrl: string) {
    // Normalize: strip trailing slash so path concatenation is predictable.
    this.relayUrl = relayUrl.replace(/\/+$/, "");
  }

  /** POST a JSON body. If `signWith` is set, the v2 signature binds to
   *  `{method: "POST", path, hash: sha256(bodyJson)}` and the
   *  `{public_key, payload, sig}` triple goes in the URL query string —
   *  the body itself stays "pure business payload" (v2 rule: the body
   *  hash must cover exactly the bytes of the request body). */
  async post<T = unknown>(
    path: string,
    body: Record<string, unknown>,
    opts: RequestOptions = {}
  ): Promise<T> {
    const bodyJson = JSON.stringify(body);
    let url = `${this.relayUrl}${path}`;
    if (opts.signWith) {
      const auth = createAuthParams(
        opts.signWith.public,
        opts.signWith.secret,
        { method: "POST", path, hash: sha256Hex(bodyJson) }
      );
      const triple = new URLSearchParams({
        public_key: auth.public_key,
        payload: auth.payload,
        sig: auth.sig,
      });
      url = `${url}?${triple.toString()}`;
    }
    return this.request<T>("POST", url, bodyJson, opts.timeoutMs);
  }

  /** GET with optional query string and optional signing. When signed,
   *  the v2 hash covers `canonicalQuery()` of the non-auth params
   *  (sorted, URL-encoded), binding the signature to exactly the
   *  query the relay will see. */
  async get<T = unknown>(
    path: string,
    opts: RequestOptions = {}
  ): Promise<T> {
    const nonAuth: Record<string, string> = {};
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v === undefined) continue;
      nonAuth[k] = String(v);
    }
    const query: Record<string, string | number | undefined> = { ...nonAuth };
    if (opts.signWith) {
      const auth = createAuthParams(
        opts.signWith.public,
        opts.signWith.secret,
        { method: "GET", path, hash: sha256Hex(canonicalQuery(nonAuth)) }
      );
      query.public_key = auth.public_key;
      query.payload = auth.payload;
      query.sig = auth.sig;
    }
    const url = `${this.relayUrl}${path}${buildQuery(query)}`;
    return this.request<T>("GET", url, null, opts.timeoutMs);
  }

  private async request<T>(
    method: "GET" | "POST",
    url: string,
    body: string | null,
    timeoutMs: number = 15_000
  ): Promise<T> {
    // Retry transient failures a few times with short backoff.
    //
    // What we retry:
    //   - transport-level fetch failures (TCP/TLS reset, DNS hiccup,
    //     fly-proxy cold-start drops) — PublicApiError with status=0
    //   - HTTP 5xx responses — fly occasionally 503s briefly during
    //     rolling deploys, and app-level 500 from a flaky write path
    //     is as likely to be transient as not
    //
    // What we surface immediately:
    //   - HTTP 4xx — the server is telling us something we sent is
    //     wrong (bad TOTP, revoked key, unknown email); retrying
    //     won't help and just makes the error take 3x longer
    //   - timeouts — already waited the full timeoutMs; retrying
    //     would likely time out again. Caller can retry at a
    //     higher level if they want to.
    const maxAttempts = 3;
    let lastErr: Error | null = null;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        return await this.requestOnce<T>(method, url, body, timeoutMs, attempt);
      } catch (err: any) {
        if (err instanceof PublicApiError) {
          // Timeouts surface as PublicApiError(status=0, timedOut=true).
          // They look like transport errors but retrying would just
          // burn another timeoutMs; caller can retry at a higher level
          // if they care.
          if (err.timedOut) throw err;
          const s = err.status;
          const retriable = s === 0 || (s >= 500 && s < 600);
          if (!retriable) throw err;
        } else if (err?.message?.includes("timed out")) {
          throw err;
        }
        lastErr = err;
        if (attempt < maxAttempts - 1) {
          const backoff = 200 * Math.pow(2, attempt); // 200, 400, 800 ms
          log("http", "retry backoff", {
            attempt,
            backoffMs: backoff,
            lastError: err?.message ?? String(err),
          });
          await new Promise((r) => setTimeout(r, backoff));
        }
      }
    }
    throw lastErr!;
  }

  private async requestOnce<T>(
    method: "GET" | "POST",
    url: string,
    body: string | null,
    timeoutMs: number,
    attempt: number
  ): Promise<T> {
    const start = now();
    const safeUrl = redactAuthQuery(url);
    log("http", `${method} start`, {
      url: safeUrl,
      attempt,
      bodyBytes: body?.length,
      timeoutMs,
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res: Response;
    try {
      res = await fetch(url, {
        method,
        body,
        headers: body === null
          ? { accept: "application/json" }
          : { "content-type": "application/json", accept: "application/json" },
        signal: controller.signal,
      });
    } catch (err: any) {
      if (err?.name === "AbortError") {
        log("http", `${method} timeout`, { url: safeUrl, attempt, ms: sinceMs(start) });
        throw new PublicApiError(
          0,
          `${method} ${url} timed out after ${timeoutMs}ms`,
          null,
          true
        );
      }
      log("http", `${method} transport error`, {
        url: safeUrl,
        attempt,
        ms: sinceMs(start),
        error: err?.message ?? String(err),
      });
      throw new PublicApiError(0, `${method} ${url}: ${err?.message ?? err}`, null);
    } finally {
      clearTimeout(timer);
    }

    const parsed = await safeJson(res);
    log("http", `${method} done`, {
      url: safeUrl,
      attempt,
      status: res.status,
      ok: res.ok,
      ms: sinceMs(start),
    });
    if (!res.ok) {
      throw new PublicApiError(
        res.status,
        extractErrorMessage(parsed, `${method} ${url} → HTTP ${res.status}`),
        parsed
      );
    }
    return parsed as T;
  }
}
