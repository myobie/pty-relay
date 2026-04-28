import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import sodium from "libsodium-wrappers-sumo";

// ── Protocol constants ──

const MSG_DATA = 0;
const MSG_ATTACH = 1;
const MSG_DETACH = 2;
const MSG_RESIZE = 3;
const MSG_EXIT = 4;
const MSG_SCREEN = 5;

const DH_LEN = 32;
const KEY_LEN = 32;
const NONCE_LEN = 12;
const HASH_LEN = 64;
const MAX_NONCE = 0xFFFFFFFFFFFFFFFFn;
const PROTOCOL_NAME = "Noise_NK_25519_ChaChaPoly_BLAKE2b";

// ── Utilities ──

function base64urlDecode(input: string): Uint8Array {
  let s = input.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function sha256hex(data: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new Uint8Array(data));
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function nonceFromCounter(n: bigint): Uint8Array {
  const buf = new Uint8Array(NONCE_LEN);
  const view = new DataView(buf.buffer);
  view.setUint32(4, Number(n & 0xFFFFFFFFn), true);
  view.setUint32(8, Number((n >> 32n) & 0xFFFFFFFFn), true);
  return buf;
}

// ── Noise NK handshake ──

class CipherState {
  k: Uint8Array | null;
  n: bigint;
  constructor(k?: Uint8Array | null) {
    this.k = k || null;
    this.n = 0n;
  }
  hasKey(): boolean {
    return this.k !== null;
  }
  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (!this.k) throw new Error("No key");
    if (this.n >= MAX_NONCE) throw new Error("Nonce exhausted");
    const nonce = nonceFromCounter(this.n);
    this.n++;
    return sodium.crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, this.k);
  }
  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (!this.k) throw new Error("No key");
    if (this.n >= MAX_NONCE) throw new Error("Nonce exhausted");
    const nonce = nonceFromCounter(this.n);
    this.n++;
    return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, this.k);
  }
}

function hmacBlake2b(key: Uint8Array, data: Uint8Array): Uint8Array {
  const blockSize = 128;
  const keyBlock = new Uint8Array(blockSize);
  if (key.length > blockSize) keyBlock.set(sodium.crypto_generichash(HASH_LEN, key, null));
  else keyBlock.set(key);
  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = keyBlock[i] ^ 54;
    opad[i] = keyBlock[i] ^ 92;
  }
  const inner = new Uint8Array(blockSize + data.length);
  inner.set(ipad);
  inner.set(data, blockSize);
  const innerHash = sodium.crypto_generichash(HASH_LEN, inner, null);
  const outer = new Uint8Array(blockSize + HASH_LEN);
  outer.set(opad);
  outer.set(innerHash, blockSize);
  return sodium.crypto_generichash(HASH_LEN, outer, null);
}

function hkdf(ck: Uint8Array, ikm: Uint8Array): [Uint8Array, Uint8Array] {
  const tempKey = hmacBlake2b(ck, ikm);
  const out1 = hmacBlake2b(tempKey, new Uint8Array([1]));
  const in2 = new Uint8Array(out1.length + 1);
  in2.set(out1);
  in2[out1.length] = 2;
  const out2 = hmacBlake2b(tempKey, in2);
  sodium.memzero(tempKey);
  return [out1, out2];
}

class SymmetricState {
  h: Uint8Array;
  ck: Uint8Array;
  cipher: CipherState;
  constructor() {
    const proto = new TextEncoder().encode(PROTOCOL_NAME);
    this.h = new Uint8Array(HASH_LEN);
    this.h.set(proto);
    this.ck = new Uint8Array(this.h);
    this.cipher = new CipherState();
  }
  mixHash(data: Uint8Array): void {
    const c = new Uint8Array(this.h.length + data.length);
    c.set(this.h);
    c.set(data, this.h.length);
    this.h = sodium.crypto_generichash(HASH_LEN, c, null);
  }
  mixKey(ikm: Uint8Array): void {
    const oldCk = this.ck;
    const [newCk, tempK] = hkdf(this.ck, ikm);
    this.ck = newCk;
    this.cipher = new CipherState(tempK.slice(0, KEY_LEN));
    sodium.memzero(oldCk);
    sodium.memzero(tempK);
    sodium.memzero(ikm);
  }
  // encryptAndHash / decryptAndHash wrap the current CipherState so the
  // empty-payload AEAD tag at the end of each handshake message is
  // transmitted and verified. Required for wire compatibility with the
  // spec-compliant TS engine in src/crypto/noise.ts.
  encryptAndHash(plaintext: Uint8Array): Uint8Array {
    if (!this.cipher.hasKey()) {
      this.mixHash(plaintext);
      return plaintext;
    }
    const ciphertext = this.cipher.encryptWithAd(this.h, plaintext);
    this.mixHash(ciphertext);
    return ciphertext;
  }
  decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    if (!this.cipher.hasKey()) {
      this.mixHash(ciphertext);
      return ciphertext;
    }
    const plaintext = this.cipher.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return plaintext;
  }
  split(): [CipherState, CipherState] {
    const [k1, k2] = hkdf(this.ck, new Uint8Array(0));
    const result: [CipherState, CipherState] = [
      new CipherState(k1.slice(0, KEY_LEN)),
      new CipherState(k2.slice(0, KEY_LEN)),
    ];
    sodium.memzero(this.ck);
    sodium.memzero(this.h);
    sodium.memzero(k1);
    sodium.memzero(k2);
    return result;
  }
}

interface Transport {
  encrypt(p: Uint8Array): Uint8Array;
  decrypt(c: Uint8Array): Uint8Array;
}

interface Handshake {
  hello: Uint8Array;
  readWelcome(welcomeMsg: Uint8Array): Transport;
}

// Noise NK initiator, wire-compatible with src/crypto/noise.ts's
// `Handshake({pattern: NK, initiator: true, ...})`. Each handshake
// message ends with encryptAndHash(empty) — a 16-byte AEAD tag — per
// Noise spec § 5.3. Both the hello we send and the welcome we parse
// carry (ephemeral + 16-byte tag).
const AEAD_TAG_LEN = 16;

function initiatorHandshake(responderPubKey: Uint8Array): Handshake {
  const ss = new SymmetricState();
  // Pre-message: responder's static is pre-known, mixed into the hash
  // before any wire bytes.
  ss.mixHash(responderPubKey);

  // -> e, es
  const { publicKey: ePub, privateKey: ePriv } = sodium.crypto_box_keypair();
  ss.mixHash(ePub);
  const dh1 = sodium.crypto_scalarmult(ePriv, responderPubKey);
  ss.mixKey(dh1);
  // encryptAndHash on an empty payload after mixKey produces just the
  // AEAD tag. Append it to the ephemeral pubkey to form the full hello.
  const helloTag = ss.encryptAndHash(new Uint8Array(0));
  const hello = concatBytes([ePub, helloTag]);

  function readWelcome(welcomeMsg: Uint8Array): Transport {
    // <- e, ee — welcome is (remote ephemeral + AEAD tag).
    if (welcomeMsg.length !== DH_LEN + AEAD_TAG_LEN) {
      throw new Error(
        `Bad WELCOME size: expected ${DH_LEN + AEAD_TAG_LEN}, got ${welcomeMsg.length}`
      );
    }
    const re = welcomeMsg.subarray(0, DH_LEN);
    const tag = welcomeMsg.subarray(DH_LEN);
    ss.mixHash(re);
    const dh2 = sodium.crypto_scalarmult(ePriv, re);
    ss.mixKey(dh2);
    // decryptAndHash verifies the AEAD tag against the current hash.
    // Its return is an empty plaintext; we only care about the side
    // effect of proving the responder saw the same transcript.
    ss.decryptAndHash(new Uint8Array(tag));
    sodium.memzero(ePriv);
    const [c1, c2] = ss.split();
    return {
      encrypt: (p: Uint8Array) => c1.encryptWithAd(new Uint8Array(0), p),
      decrypt: (c: Uint8Array) => c2.decryptWithAd(new Uint8Array(0), c),
    };
  }
  return { hello, readWelcome };
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

// ── PTY packet framing ──

function makePacket(type: number, payload: Uint8Array | ArrayBuffer): Uint8Array {
  const p = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  const buf = new ArrayBuffer(5 + p.byteLength);
  const view = new DataView(buf);
  view.setUint8(0, type);
  view.setUint32(1, p.byteLength, false);
  new Uint8Array(buf, 5).set(p);
  return new Uint8Array(buf);
}

function makeAttach(rows: number, cols: number): Uint8Array {
  const p = new ArrayBuffer(4);
  const v = new DataView(p);
  v.setUint16(0, rows, false);
  v.setUint16(2, cols, false);
  return makePacket(MSG_ATTACH, new Uint8Array(p));
}

function makeResize(rows: number, cols: number): Uint8Array {
  const p = new ArrayBuffer(4);
  const v = new DataView(p);
  v.setUint16(0, rows, false);
  v.setUint16(2, cols, false);
  return makePacket(MSG_RESIZE, new Uint8Array(p));
}

function makeData(text: string): Uint8Array {
  return makePacket(MSG_DATA, new TextEncoder().encode(text));
}

function makeDetach(): Uint8Array {
  return makePacket(MSG_DETACH, new Uint8Array(0));
}

interface Packet {
  type: number;
  payload: Uint8Array;
}

class PacketParser {
  buf: Uint8Array;
  constructor() {
    this.buf = new Uint8Array(0);
  }
  feed(data: Uint8Array): Packet[] {
    const combined = new Uint8Array(this.buf.length + data.length);
    combined.set(this.buf);
    combined.set(data, this.buf.length);
    this.buf = combined;
    const packets: Packet[] = [];
    while (this.buf.length >= 5) {
      const view = new DataView(this.buf.buffer, this.buf.byteOffset);
      const type = view.getUint8(0);
      const len = view.getUint32(1, false);
      if (this.buf.length < 5 + len) break;
      packets.push({ type, payload: this.buf.slice(5, 5 + len) });
      this.buf = this.buf.slice(5 + len);
    }
    return packets;
  }
}

// ── Client token storage ──
//
// Local storage for client approval tokens.
//
// Keyed by host + publicKey prefix so different daemons don't collide.
// The pairing secret isn't part of the key because it's effectively
// constant per-daemon for the life of an install, and including it
// would leak it into storage enumeration.
//
// We store tokens here so the user can bookmark the base URL (without
// an embedded client token) and still get auto-approved on return
// visits. This is important because embedding the client token in the
// URL would leak it through Chrome sync, screenshots, shell history,
// etc.

const CLIENT_TOKEN_STORAGE_KEY = "pty-relay:client-tokens";

function clientTokenStorageKey(host: string, publicKeyB64: string): string {
  // Use first 16 chars of the base64url public key as a stable short id.
  const keyId = publicKeyB64.slice(0, 16);
  return `${host}:${keyId}`;
}

function loadStoredClientToken(host: string, publicKeyB64: string): string | null {
  try {
    const raw = localStorage.getItem(CLIENT_TOKEN_STORAGE_KEY);
    if (!raw) return null;
    const map = JSON.parse(raw) as Record<string, string>;
    return map[clientTokenStorageKey(host, publicKeyB64)] ?? null;
  } catch {
    return null;
  }
}

function saveStoredClientToken(host: string, publicKeyB64: string, clientToken: string): void {
  try {
    const raw = localStorage.getItem(CLIENT_TOKEN_STORAGE_KEY);
    const map = (raw ? JSON.parse(raw) : {}) as Record<string, string>;
    map[clientTokenStorageKey(host, publicKeyB64)] = clientToken;
    localStorage.setItem(CLIENT_TOKEN_STORAGE_KEY, JSON.stringify(map));
  } catch {}
}

function deleteStoredClientToken(host: string, publicKeyB64: string): void {
  try {
    const raw = localStorage.getItem(CLIENT_TOKEN_STORAGE_KEY);
    if (!raw) return;
    const map = JSON.parse(raw) as Record<string, string>;
    const key = clientTokenStorageKey(host, publicKeyB64);
    if (key in map) {
      delete map[key];
      localStorage.setItem(CLIENT_TOKEN_STORAGE_KEY, JSON.stringify(map));
    }
  } catch {}
}

// ── Token parsing ──

interface Token {
  host: string;
  session: string | null;
  publicKey: Uint8Array;
  publicKeyB64: string;
  secret: Uint8Array;
  clientToken: string | null;
}

declare global {
  interface Window {
    PTY_RELAY_TOKEN?: Token;
    __ptyRelayWs?: WebSocket;
  }
  interface Navigator {
    userAgentData?: { platform?: string };
  }
}

function parseToken(): Token | null {
  if (window.PTY_RELAY_TOKEN) return window.PTY_RELAY_TOKEN;
  const fragment = window.location.hash.slice(1);
  if (!fragment || !fragment.includes(".")) return null;
  const parts = fragment.split(".");
  if (parts.length < 2 || parts.length > 3) return null;
  const [keyB64, secretB64] = parts;
  // Prefer a fragment-supplied token (e.g. from a pre-auth invite URL).
  // Fall back to a locally stored one for the bookmarked case.
  let clientToken: string | null = parts.length === 3 ? parts[2] : null;
  if (!clientToken) {
    clientToken = loadStoredClientToken(window.location.host, keyB64);
  }
  try {
    const publicKey = base64urlDecode(keyB64);
    const secret = base64urlDecode(secretB64);
    if (publicKey.length !== 32 || secret.length !== 32) return null;
    const pathSession = window.location.pathname.slice(1);
    return {
      host: window.location.host,
      session: pathSession || null,
      publicKey,
      publicKeyB64: keyB64,
      secret,
      clientToken,
    };
  } catch {
    return null;
  }
}

// ── DOM refs ──

const statusOverlay = document.getElementById("status-overlay")!;
const sessionListView = document.getElementById("session-list")!;
const terminalView = document.getElementById("terminal-view")!;
const sessionsContainer = document.getElementById("sessions-container")!;
const sessionNameLabel = document.getElementById("session-name-label")!;
const terminalContainer = document.getElementById("terminal-container")!;
const detachBtn = document.getElementById("detach-btn")!;

type View = "loading" | "sessions" | "terminal";

function showView(view: View): void {
  statusOverlay.style.display = "none";
  sessionListView.style.display = "none";
  terminalView.style.display = "none";
  if (view === "loading") statusOverlay.style.display = "flex";
  else if (view === "sessions") sessionListView.style.display = "flex";
  else if (view === "terminal") terminalView.style.display = "flex";
}

function showStatus(msg: string): void {
  statusOverlay.textContent = msg;
  showView("loading");
}

function updateVh(): void {
  const vh = window.visualViewport?.height ?? window.innerHeight;
  document.documentElement.style.setProperty("--vh", `${vh}px`);
}

window.visualViewport?.addEventListener("resize", updateVh);
window.visualViewport?.addEventListener("scroll", updateVh);
window.addEventListener("resize", updateVh);
updateVh();

// ── Connection state ──

let transport: Transport | null = null;
let ws: WebSocket | null = null;
let term: Terminal | null = null;
let fitAddon: FitAddon | null = null;
let packetParser = new PacketParser();
let resizeObserver: ResizeObserver | null = null;
let sessionAttached = false;

// Static document.title used when nothing is attached. We restore it
// on detach so the browser tab stops claiming a stale session/OSC title.
const DEFAULT_DOC_TITLE = "pty relay";

/** Wire xterm.js's OSC 0/2 (terminal title) hook to document.title so
 *  the browser tab reflects what a native terminal would show in its
 *  window title. Falls back to the session name if the program clears
 *  the title (empty OSC). */
function bindTerminalTitle(t: Terminal, fallbackName: string): void {
  t.onTitleChange((title) => {
    document.title = (title && title.length > 0) ? title : fallbackName;
  });
}

function sendEncrypted(data: Uint8Array | string): void {
  if (!transport || !ws || ws.readyState !== WebSocket.OPEN) return;
  const ct = transport.encrypt(
    data instanceof Uint8Array ? data : new TextEncoder().encode(data)
  );
  ws.send(ct);
}

function sendJson(obj: unknown): void {
  sendEncrypted(new TextEncoder().encode(JSON.stringify(obj)));
}

function sendPtyPacket(packet: Uint8Array): void {
  sendEncrypted(packet);
}

function disconnect(): void {
  intentionalDisconnect = true;
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  document.title = DEFAULT_DOC_TITLE;
  if (term) {
    term.dispose();
    term = null;
  }
  if (fitAddon) {
    fitAddon = null;
  }
  if (resizeObserver) {
    resizeObserver.disconnect();
    resizeObserver = null;
  }
  if (ws) {
    ws.close();
    ws = null;
  }
  transport = null;
  sessionAttached = false;
  currentSession = null;
  packetParser = new PacketParser();
}

function attachToSession(sessionName: string, _cols: number, _rows: number): void {
  currentSession = sessionName;
  sessionNameLabel.textContent = sessionName;
  // Default tab title to the session name on attach. If the running
  // program emits OSC 0/2 we'll override via bindTerminalTitle below.
  document.title = sessionName;
  showView("terminal");
  if (!term) {
    term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      smoothScrollDuration: 80,
      theme: { background: "#0a0a0a" },
    });
    fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalContainer as HTMLElement);
    fitAddon.fit();
    resizeObserver = new ResizeObserver(() => {
      if (fitAddon && term) fitAddon.fit();
    });
    resizeObserver.observe(terminalContainer);
    term.onResize(({ cols: cols2, rows: rows2 }) => {
      if (sessionAttached) sendPtyPacket(makeResize(rows2, cols2));
    });
    term.onData((data) => {
      if (sessionAttached) sendPtyPacket(makeData(data));
    });
    bindTerminalTitle(term, sessionName);
  }
  sendJson({
    type: "attach",
    session: sessionName,
    cols: term.cols,
    rows: term.rows,
  });
}

function handleDecryptedMessage(plaintext: Uint8Array): void {
  if (!sessionAttached) {
    try {
      const msg = JSON.parse(new TextDecoder().decode(plaintext));
      if (msg.type === "approved" && msg.client_token) {
        // Save the client token to localStorage, NOT the URL. Keeping
        // the token out of the URL means the user can safely bookmark
        // the base URL without leaking the credential via Chrome sync,
        // screenshots, or shell history.
        if (token) {
          token.clientToken = msg.client_token;
          saveStoredClientToken(token.host, token.publicKeyB64, msg.client_token);
        }
        return;
      } else if (msg.type === "attached") {
        sessionAttached = true;
        if (term) term.focus();
        return;
      } else if (msg.type === "spawned") {
        currentSession = msg.session;
        sessionNameLabel.textContent = msg.session;
        document.title = msg.session;
        showView("terminal");
        if (!term) {
          term = new Terminal({
            cursorBlink: true,
            fontSize: 14,
            smoothScrollDuration: 80,
            theme: { background: "#0a0a0a" },
          });
          fitAddon = new FitAddon();
          term.loadAddon(fitAddon);
          term.open(terminalContainer as HTMLElement);
          fitAddon.fit();
          resizeObserver = new ResizeObserver(() => {
            if (fitAddon && term) fitAddon.fit();
          });
          resizeObserver.observe(terminalContainer);
          term.onResize(({ cols, rows }) => {
            if (sessionAttached) sendPtyPacket(makeResize(rows, cols));
          });
          term.onData((data) => {
            if (sessionAttached) sendPtyPacket(makeData(data));
          });
          bindTerminalTitle(term, msg.session);
        }
        return;
      } else if (msg.type === "sessions") {
        renderSessionList(msg.sessions);
        return;
      } else if (msg.type === "error") {
        showStatus(`Error: ${msg.message}`);
        return;
      }
    } catch {}
  }
  const packets = packetParser.feed(plaintext);
  for (const pkt of packets) {
    switch (pkt.type) {
      case MSG_DATA:
        if (term) term.write(pkt.payload);
        break;
      case MSG_SCREEN:
        if (term) {
          term.write("\x1B[2J\x1B[H");
          term.write(pkt.payload);
        }
        break;
      case MSG_EXIT: {
        const code =
          pkt.payload.length >= 4
            ? new DataView(pkt.payload.buffer, pkt.payload.byteOffset).getInt32(0, false)
            : -1;
        showStatus(`Session exited (code ${code})`);
        disconnect();
        break;
      }
    }
  }
}

import {
  renderSessionList as renderSessionListView,
  type SessionMeta,
} from "./session-list-view.ts";

function spawnSession(name: string, cwd?: string): void {
  showStatus("Starting session...");
  const msg: { type: string; name: string; cwd?: string } = { type: "spawn", name };
  if (cwd) msg.cwd = cwd;
  sendJson(msg);
}

function renderSessionList(sessions: SessionMeta[]): void {
  renderSessionListView(sessionsContainer, sessions, {
    onAttach: (name) => {
      const cols = Math.floor(terminalContainer.clientWidth / 9) || 80;
      const rows = Math.floor(terminalContainer.clientHeight / 17) || 24;
      attachToSession(name, cols, rows);
    },
    onSpawn: () => {
      const name = prompt("Session name:", `shell-${Date.now() % 1e4}`);
      if (!name) return;
      const cwd = prompt("Working directory:", "~");
      spawnSession(name.trim(), cwd && cwd !== "~" ? cwd : undefined);
    },
  });
  showView("sessions");
}

detachBtn.addEventListener("click", () => {
  if (sessionAttached) sendPtyPacket(makeDetach());
  sessionAttached = false;
  currentSession = null;
  document.title = DEFAULT_DOC_TITLE;
  packetParser = new PacketParser();
  if (term) {
    term.dispose();
    term = null;
  }
  if (fitAddon) {
    fitAddon = null;
  }
  if (resizeObserver) {
    resizeObserver.disconnect();
    resizeObserver = null;
  }
  showStatus("Loading sessions...");
  sendJson({ type: "list" });
});

// ── Mobile keyboard bar ──

const quickBar = document.getElementById("quick-bar")!;
const keyPanel = document.getElementById("key-panel")!;
const textInputBar = document.getElementById("text-input-bar")!;
const textInput = document.getElementById("text-input") as HTMLInputElement;
const textSendBtn = document.getElementById("text-send-btn")!;
const textBackBtn = document.getElementById("text-back-btn")!;
const kbReopen = document.getElementById("kb-reopen")!;
const keyboard = document.getElementById("keyboard")!;

let stickyCtrl = false;
let lockedCtrl = false;
let lastCtrlTap = 0;
let stickyAlt = false;
let lockedAlt = false;
let lastAltTap = 0;
let kbMode: "bar" | "panel" | "text" | "hidden" = "bar";

function preventFocusSteal(e: Event): void {
  e.preventDefault();
}

function sendKey(initial: string): void {
  let seq = initial;
  if (stickyAlt && !lockedAlt) {
    seq = "\x1B" + seq;
    stickyAlt = false;
    updateModifierButtons();
  } else if (stickyAlt && lockedAlt) {
    seq = "\x1B" + seq;
  }
  if (stickyCtrl && seq.length === 1) {
    const lower = seq.toLowerCase();
    if (lower >= "a" && lower <= "z") {
      seq = String.fromCharCode(lower.charCodeAt(0) - 96);
    }
    if (!lockedCtrl) {
      stickyCtrl = false;
      updateModifierButtons();
    }
  }
  if (sessionAttached) sendPtyPacket(makeData(seq));
  if (term) term.focus();
}

function toggleModifier(which: "ctrl" | "alt"): void {
  const now = Date.now();
  if (which === "ctrl") {
    if (now - lastCtrlTap < 400) {
      lockedCtrl = !lockedCtrl;
      stickyCtrl = lockedCtrl;
      lastCtrlTap = 0;
    } else {
      if (lockedCtrl) {
        lockedCtrl = false;
        stickyCtrl = false;
      } else {
        stickyCtrl = !stickyCtrl;
      }
      lastCtrlTap = now;
    }
  } else {
    if (now - lastAltTap < 400) {
      lockedAlt = !lockedAlt;
      stickyAlt = lockedAlt;
      lastAltTap = 0;
    } else {
      if (lockedAlt) {
        lockedAlt = false;
        stickyAlt = false;
      } else {
        stickyAlt = !stickyAlt;
      }
      lastAltTap = now;
    }
  }
  updateModifierButtons();
}

let ctrlBtn: HTMLButtonElement | undefined;
let altBtn: HTMLButtonElement | undefined;

function updateModifierButtons(): void {
  if (ctrlBtn) {
    ctrlBtn.className = "kb-btn" + (lockedCtrl ? " locked" : stickyCtrl ? " active" : "");
  }
  if (altBtn) {
    altBtn.className = "kb-btn" + (lockedAlt ? " locked" : stickyAlt ? " active" : "");
  }
}

function setKbMode(mode: "bar" | "panel" | "text" | "hidden"): void {
  kbMode = mode;
  quickBar.style.display = mode === "bar" ? "flex" : "none";
  keyPanel.style.display = mode === "panel" ? "grid" : "none";
  textInputBar.style.display = mode === "text" ? "flex" : "none";
  keyboard.style.display = mode === "hidden" ? "none" : "";
  kbReopen.style.display = mode === "hidden" ? "block" : "none";
  if (mode === "panel") (document.activeElement as HTMLElement | null)?.blur();
  if (mode === "text") textInput.focus();
  if (mode === "bar" && term) term.focus();
  updateVh();
}

interface KeyDef {
  label: string;
  seq?: string;
  action?: () => void;
  id?: string;
}

function buildQuickBar(): void {
  const keys: KeyDef[] = [
    { label: "Txt", action: () => setKbMode("text") },
    { label: "Esc", seq: "\x1B" },
    { label: "Tab", seq: "\t" },
    { label: "Ctrl", action: () => toggleModifier("ctrl"), id: "ctrl" },
    { label: "Alt", action: () => toggleModifier("alt"), id: "alt" },
    { label: "|", seq: "|" },
    { label: "-", seq: "-" },
    { label: "/", seq: "/" },
    { label: "~", seq: "~" },
    { label: "\u2190", seq: "\x1B[D" },
    { label: "\u2192", seq: "\x1B[C" },
    { label: "\u2191", seq: "\x1B[A" },
    { label: "\u2193", seq: "\x1B[B" },
    { label: "Home", seq: "\x1B[H" },
    { label: "End", seq: "\x1B[F" },
    { label: "\u2328", action: () => setKbMode("panel") },
    { label: "\u2715", action: () => setKbMode("hidden") },
  ];
  for (const k of keys) {
    const btn = document.createElement("button");
    btn.className = "kb-btn";
    btn.textContent = k.label;
    btn.addEventListener("mousedown", preventFocusSteal);
    if (k.seq) btn.addEventListener("click", () => sendKey(k.seq!));
    else if (k.action) btn.addEventListener("click", k.action);
    if (k.id === "ctrl") ctrlBtn = btn;
    if (k.id === "alt") altBtn = btn;
    quickBar.appendChild(btn);
  }
}

function buildKeyPanel(): void {
  const keys: KeyDef[] = [
    { label: "\u25BE Bar", action: () => setKbMode("bar") },
    { label: "S+Tab", seq: "\x1B[Z" },
    { label: "Ins", seq: "\x1B[2~" },
    { label: "Del", seq: "\x1B[3~" },
    { label: "PgUp", seq: "\x1B[5~" },
    { label: "PgDn", seq: "\x1B[6~" },
    { label: "^C", seq: "" },
    { label: "^D", seq: "" },
    { label: "^Z", seq: "" },
    { label: "^L", seq: "\f" },
    { label: "^A", seq: "" },
    { label: "^E", seq: "" },
    { label: "^S", seq: "" },
    { label: "^Q", seq: "" },
    { label: "^R", seq: "" },
    { label: "^W", seq: "" },
    { label: "^U", seq: "" },
    { label: "^K", seq: "\v" },
    { label: "F1", seq: "\x1BOP" },
    { label: "F2", seq: "\x1BOQ" },
    { label: "F3", seq: "\x1BOR" },
    { label: "F4", seq: "\x1BOS" },
    { label: "F5", seq: "\x1B[15~" },
    { label: "F6", seq: "\x1B[17~" },
    { label: "F7", seq: "\x1B[18~" },
    { label: "F8", seq: "\x1B[19~" },
    { label: "F9", seq: "\x1B[20~" },
    { label: "F10", seq: "\x1B[21~" },
    { label: "F11", seq: "\x1B[23~" },
    { label: "F12", seq: "\x1B[24~" },
    { label: "A+\u2190", seq: "\x1B\x1B[D" },
    { label: "A+\u2192", seq: "\x1B\x1B[C" },
    { label: "{", seq: "{" },
    { label: "}", seq: "}" },
    { label: "[", seq: "[" },
    { label: "]", seq: "]" },
    { label: "<", seq: "<" },
    { label: ">", seq: ">" },
    { label: "`", seq: "`" },
    { label: "\\", seq: "\\" },
    {
      label: "Paste",
      action: async () => {
        try {
          const text = await navigator.clipboard.readText();
          if (text) sendKey(text);
        } catch {}
      },
    },
  ];
  for (const k of keys) {
    const btn = document.createElement("button");
    btn.className = "kb-btn";
    btn.textContent = k.label;
    btn.addEventListener("mousedown", preventFocusSteal);
    if (k.seq) btn.addEventListener("click", () => sendKey(k.seq!));
    else if (k.action) btn.addEventListener("click", k.action);
    keyPanel.appendChild(btn);
  }
}

textSendBtn.addEventListener("click", () => {
  const val = textInput.value;
  if (val) {
    sendKey(val + "\r");
    textInput.value = "";
  }
});
textInput.addEventListener("keydown", (e: KeyboardEvent) => {
  if (e.key === "Enter") {
    e.preventDefault();
    (textSendBtn as HTMLButtonElement).click();
  }
});
textBackBtn.addEventListener("click", () => setKbMode("bar"));
kbReopen.addEventListener("click", () => setKbMode("bar"));
buildQuickBar();
buildKeyPanel();

// ── Touch scroll with inertia ──

let touchStartY = 0;
let scrollPixelOffset = 0;
let touchVelocity = 0;
let lastTouchY = 0;
let lastTouchTime = 0;
let inertiaFrame: number | null = null;

function getLineHeight(): number {
  if (term) {
    const canvas = terminalContainer.querySelector("canvas") as HTMLCanvasElement | null;
    if (canvas) return canvas.clientHeight / term.rows;
  }
  return 14 * 1.2;
}

function scrollByPixels(dy: number): void {
  if (!term) return;
  scrollPixelOffset += dy;
  const lh = getLineHeight();
  const lines = Math.trunc(scrollPixelOffset / lh);
  if (lines !== 0) {
    term.scrollLines(lines);
    scrollPixelOffset -= lines * lh;
  }
}

terminalContainer.addEventListener(
  "touchstart",
  (e: TouchEvent) => {
    if (inertiaFrame) {
      cancelAnimationFrame(inertiaFrame);
      inertiaFrame = null;
    }
    touchStartY = e.touches[0].clientY;
    lastTouchY = touchStartY;
    lastTouchTime = Date.now();
    touchVelocity = 0;
    scrollPixelOffset = 0;
  },
  { passive: true }
);
terminalContainer.addEventListener(
  "touchmove",
  (e: TouchEvent) => {
    const y = e.touches[0].clientY;
    const dy = lastTouchY - y;
    scrollByPixels(dy);
    const now = Date.now();
    const dt = now - lastTouchTime;
    if (dt > 0) touchVelocity = dy / dt;
    lastTouchY = y;
    lastTouchTime = now;
  },
  { passive: true }
);
terminalContainer.addEventListener(
  "touchend",
  () => {
    if (Math.abs(touchVelocity) < 0.01) return;
    let vel = touchVelocity * 16;
    let lastFrame = performance.now();
    function inertia(now: number): void {
      const dt = now - lastFrame;
      lastFrame = now;
      scrollByPixels(vel);
      vel *= Math.max(0, 1 - 5e-3 * dt);
      if (Math.abs(vel) > 0.5) inertiaFrame = requestAnimationFrame(inertia);
      else inertiaFrame = null;
    }
    inertiaFrame = requestAnimationFrame(inertia);
  },
  { passive: true }
);

// ── Connection / reconnect ──

let token: Token | null = null;
let currentSession: string | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectDelay = 1e3;
let intentionalDisconnect = false;

function scheduleReconnect(): void {
  if (intentionalDisconnect || !token) return;
  if (reconnectTimer) clearTimeout(reconnectTimer);
  const delay = Math.min(reconnectDelay, 1e4);
  showStatus(`Reconnecting in ${Math.round(delay / 1e3)}s...`);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    reconnectDelay = Math.min(reconnectDelay * 1.5, 1e4);
    connectToRelay();
  }, delay);
}

function connectToRelay(): void {
  if (!token) return;
  if (ws) {
    ws.close();
    ws = null;
  }
  transport = null;
  sessionAttached = false;
  packetParser = new PacketParser();
  showStatus("Connecting...");
  const handshake = initiatorHandshake(token.publicKey);
  let handshakeComplete = false;
  sha256hex(token.secret).then((secretHash) => {
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    let wsUrl = `${scheme}://${token!.host}/ws?role=client&secret_hash=${secretHash}`;
    if (token!.clientToken) {
      wsUrl += `&client_token=${encodeURIComponent(token!.clientToken)}`;
    }
    ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";
    window.__ptyRelayWs = ws;
    ws.onopen = () => {
      showStatus("Waiting for daemon...");
    };
    ws.onmessage = (event: MessageEvent) => {
      if (typeof event.data === "string") {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "paired") {
            showStatus("Handshaking...");
            ws!.send(handshake.hello);
          } else if (msg.type === "waiting_for_approval") {
            showStatus("Waiting for operator approval...");
          } else if (msg.type === "draining") {
            showStatus("Server updating...");
          } else if (msg.type === "peer_disconnected") {
            showStatus("Daemon disconnected");
            scheduleReconnect();
          } else if (msg.type === "error") {
            // If the daemon revoked our stored token, drop it from
            // localStorage and reload so we start fresh (back into the
            // approval queue without a stale credential).
            if (
              /token revoked/i.test(msg.message || "") &&
              token &&
              token.clientToken
            ) {
              deleteStoredClientToken(token.host, token.publicKeyB64);
              showStatus("Access was revoked — reloading...");
              setTimeout(() => window.location.reload(), 800);
            } else {
              showStatus(`Error: ${msg.message}`);
            }
          }
        } catch {}
      } else {
        const data = new Uint8Array(event.data as ArrayBuffer);
        if (!handshakeComplete) {
          try {
            transport = handshake.readWelcome(data);
            handshakeComplete = true;
            reconnectDelay = 1e3;
            sendJson({
              type: "hello",
              client: "web",
              os: navigator.userAgentData?.platform || navigator.platform || "unknown",
              label: navigator.userAgent.split(" ").pop() || "browser",
            });
            const sessionToAttach = currentSession || token!.session;
            if (sessionToAttach) {
              const cols = term?.cols || Math.floor(terminalContainer.clientWidth / 9) || 80;
              const rows = term?.rows || Math.floor(terminalContainer.clientHeight / 17) || 24;
              attachToSession(sessionToAttach, cols, rows);
            } else {
              showStatus("Loading sessions...");
              sendJson({ type: "list" });
            }
          } catch (err) {
            showStatus(`Handshake failed: ${(err as Error).message}`);
            scheduleReconnect();
          }
        } else if (transport) {
          try {
            const plaintext = transport.decrypt(data);
            handleDecryptedMessage(plaintext);
          } catch (err) {
            showStatus(`Decryption failed: ${(err as Error).message}`);
            scheduleReconnect();
          }
        }
      }
    };
    ws.onerror = () => {};
    ws.onclose = (event: CloseEvent) => {
      if (event.code === 1012) {
        showStatus("Server updating...");
        reconnectDelay = 500;
        scheduleReconnect();
        return;
      }
      if (handshakeComplete && !intentionalDisconnect) {
        scheduleReconnect();
      }
    };
  });
}

async function main(): Promise<void> {
  await sodium.ready;
  token = parseToken();
  if (!token) {
    showStatus("Invalid token URL. Expected: https://host/session#key.secret");
    return;
  }
  connectToRelay();
}

main();
