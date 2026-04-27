// browser/src/main.ts
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import sodium from "libsodium-wrappers-sumo";
var MSG_DATA = 0;
var MSG_DETACH = 2;
var MSG_RESIZE = 3;
var MSG_EXIT = 4;
var MSG_SCREEN = 5;
var DH_LEN = 32;
var KEY_LEN = 32;
var NONCE_LEN = 12;
var HASH_LEN = 64;
var MAX_NONCE = 0xFFFFFFFFFFFFFFFFn;
var PROTOCOL_NAME = "Noise_NK_25519_ChaChaPoly_BLAKE2b";
function base64urlDecode(input) {
  let s = input.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
async function sha256hex(data) {
  const hash = await crypto.subtle.digest("SHA-256", new Uint8Array(data));
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function nonceFromCounter(n) {
  const buf = new Uint8Array(NONCE_LEN);
  const view = new DataView(buf.buffer);
  view.setUint32(4, Number(n & 0xFFFFFFFFn), true);
  view.setUint32(8, Number(n >> 32n & 0xFFFFFFFFn), true);
  return buf;
}
var CipherState = class {
  k;
  n;
  constructor(k) {
    this.k = k || null;
    this.n = 0n;
  }
  hasKey() {
    return this.k !== null;
  }
  encryptWithAd(ad, plaintext) {
    if (!this.k) throw new Error("No key");
    if (this.n >= MAX_NONCE) throw new Error("Nonce exhausted");
    const nonce = nonceFromCounter(this.n);
    this.n++;
    return sodium.crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, this.k);
  }
  decryptWithAd(ad, ciphertext) {
    if (!this.k) throw new Error("No key");
    if (this.n >= MAX_NONCE) throw new Error("Nonce exhausted");
    const nonce = nonceFromCounter(this.n);
    this.n++;
    return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, this.k);
  }
};
function hmacBlake2b(key, data) {
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
function hkdf(ck, ikm) {
  const tempKey = hmacBlake2b(ck, ikm);
  const out1 = hmacBlake2b(tempKey, new Uint8Array([1]));
  const in2 = new Uint8Array(out1.length + 1);
  in2.set(out1);
  in2[out1.length] = 2;
  const out2 = hmacBlake2b(tempKey, in2);
  sodium.memzero(tempKey);
  return [out1, out2];
}
var SymmetricState = class {
  h;
  ck;
  cipher;
  constructor() {
    const proto = new TextEncoder().encode(PROTOCOL_NAME);
    this.h = new Uint8Array(HASH_LEN);
    this.h.set(proto);
    this.ck = new Uint8Array(this.h);
    this.cipher = new CipherState();
  }
  mixHash(data) {
    const c = new Uint8Array(this.h.length + data.length);
    c.set(this.h);
    c.set(data, this.h.length);
    this.h = sodium.crypto_generichash(HASH_LEN, c, null);
  }
  mixKey(ikm) {
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
  encryptAndHash(plaintext) {
    if (!this.cipher.hasKey()) {
      this.mixHash(plaintext);
      return plaintext;
    }
    const ciphertext = this.cipher.encryptWithAd(this.h, plaintext);
    this.mixHash(ciphertext);
    return ciphertext;
  }
  decryptAndHash(ciphertext) {
    if (!this.cipher.hasKey()) {
      this.mixHash(ciphertext);
      return ciphertext;
    }
    const plaintext = this.cipher.decryptWithAd(this.h, ciphertext);
    this.mixHash(ciphertext);
    return plaintext;
  }
  split() {
    const [k1, k2] = hkdf(this.ck, new Uint8Array(0));
    const result = [
      new CipherState(k1.slice(0, KEY_LEN)),
      new CipherState(k2.slice(0, KEY_LEN))
    ];
    sodium.memzero(this.ck);
    sodium.memzero(this.h);
    sodium.memzero(k1);
    sodium.memzero(k2);
    return result;
  }
};
var AEAD_TAG_LEN = 16;
function initiatorHandshake(responderPubKey) {
  const ss = new SymmetricState();
  ss.mixHash(responderPubKey);
  const { publicKey: ePub, privateKey: ePriv } = sodium.crypto_box_keypair();
  ss.mixHash(ePub);
  const dh1 = sodium.crypto_scalarmult(ePriv, responderPubKey);
  ss.mixKey(dh1);
  const helloTag = ss.encryptAndHash(new Uint8Array(0));
  const hello = concatBytes([ePub, helloTag]);
  function readWelcome(welcomeMsg) {
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
    ss.decryptAndHash(new Uint8Array(tag));
    sodium.memzero(ePriv);
    const [c1, c2] = ss.split();
    return {
      encrypt: (p) => c1.encryptWithAd(new Uint8Array(0), p),
      decrypt: (c) => c2.decryptWithAd(new Uint8Array(0), c)
    };
  }
  return { hello, readWelcome };
}
function concatBytes(chunks) {
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
function makePacket(type, payload) {
  const p = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  const buf = new ArrayBuffer(5 + p.byteLength);
  const view = new DataView(buf);
  view.setUint8(0, type);
  view.setUint32(1, p.byteLength, false);
  new Uint8Array(buf, 5).set(p);
  return new Uint8Array(buf);
}
function makeResize(rows, cols) {
  const p = new ArrayBuffer(4);
  const v = new DataView(p);
  v.setUint16(0, rows, false);
  v.setUint16(2, cols, false);
  return makePacket(MSG_RESIZE, new Uint8Array(p));
}
function makeData(text) {
  return makePacket(MSG_DATA, new TextEncoder().encode(text));
}
function makeDetach() {
  return makePacket(MSG_DETACH, new Uint8Array(0));
}
var PacketParser = class {
  buf;
  constructor() {
    this.buf = new Uint8Array(0);
  }
  feed(data) {
    const combined = new Uint8Array(this.buf.length + data.length);
    combined.set(this.buf);
    combined.set(data, this.buf.length);
    this.buf = combined;
    const packets = [];
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
};
var CLIENT_TOKEN_STORAGE_KEY = "pty-relay:client-tokens";
function clientTokenStorageKey(host, publicKeyB64) {
  const keyId = publicKeyB64.slice(0, 16);
  return `${host}:${keyId}`;
}
function loadStoredClientToken(host, publicKeyB64) {
  try {
    const raw = localStorage.getItem(CLIENT_TOKEN_STORAGE_KEY);
    if (!raw) return null;
    const map = JSON.parse(raw);
    return map[clientTokenStorageKey(host, publicKeyB64)] ?? null;
  } catch {
    return null;
  }
}
function saveStoredClientToken(host, publicKeyB64, clientToken) {
  try {
    const raw = localStorage.getItem(CLIENT_TOKEN_STORAGE_KEY);
    const map = raw ? JSON.parse(raw) : {};
    map[clientTokenStorageKey(host, publicKeyB64)] = clientToken;
    localStorage.setItem(CLIENT_TOKEN_STORAGE_KEY, JSON.stringify(map));
  } catch {
  }
}
function deleteStoredClientToken(host, publicKeyB64) {
  try {
    const raw = localStorage.getItem(CLIENT_TOKEN_STORAGE_KEY);
    if (!raw) return;
    const map = JSON.parse(raw);
    const key = clientTokenStorageKey(host, publicKeyB64);
    if (key in map) {
      delete map[key];
      localStorage.setItem(CLIENT_TOKEN_STORAGE_KEY, JSON.stringify(map));
    }
  } catch {
  }
}
function parseToken() {
  if (window.PTY_RELAY_TOKEN) return window.PTY_RELAY_TOKEN;
  const fragment = window.location.hash.slice(1);
  if (!fragment || !fragment.includes(".")) return null;
  const parts = fragment.split(".");
  if (parts.length < 2 || parts.length > 3) return null;
  const [keyB64, secretB64] = parts;
  let clientToken = parts.length === 3 ? parts[2] : null;
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
      clientToken
    };
  } catch {
    return null;
  }
}
var statusOverlay = document.getElementById("status-overlay");
var sessionListView = document.getElementById("session-list");
var terminalView = document.getElementById("terminal-view");
var sessionsContainer = document.getElementById("sessions-container");
var sessionNameLabel = document.getElementById("session-name-label");
var terminalContainer = document.getElementById("terminal-container");
var detachBtn = document.getElementById("detach-btn");
function showView(view) {
  statusOverlay.style.display = "none";
  sessionListView.style.display = "none";
  terminalView.style.display = "none";
  if (view === "loading") statusOverlay.style.display = "flex";
  else if (view === "sessions") sessionListView.style.display = "flex";
  else if (view === "terminal") terminalView.style.display = "flex";
}
function showStatus(msg) {
  statusOverlay.textContent = msg;
  showView("loading");
}
function updateVh() {
  const vh = window.visualViewport?.height ?? window.innerHeight;
  document.documentElement.style.setProperty("--vh", `${vh}px`);
}
window.visualViewport?.addEventListener("resize", updateVh);
window.visualViewport?.addEventListener("scroll", updateVh);
window.addEventListener("resize", updateVh);
updateVh();
var transport = null;
var ws = null;
var term = null;
var fitAddon = null;
var packetParser = new PacketParser();
var resizeObserver = null;
var sessionAttached = false;
function sendEncrypted(data) {
  if (!transport || !ws || ws.readyState !== WebSocket.OPEN) return;
  const ct = transport.encrypt(
    data instanceof Uint8Array ? data : new TextEncoder().encode(data)
  );
  ws.send(ct);
}
function sendJson(obj) {
  sendEncrypted(new TextEncoder().encode(JSON.stringify(obj)));
}
function sendPtyPacket(packet) {
  sendEncrypted(packet);
}
function disconnect() {
  intentionalDisconnect = true;
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
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
function attachToSession(sessionName, _cols, _rows) {
  currentSession = sessionName;
  sessionNameLabel.textContent = sessionName;
  showView("terminal");
  if (!term) {
    term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      smoothScrollDuration: 80,
      theme: { background: "#0a0a0a" }
    });
    fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalContainer);
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
  }
  sendJson({
    type: "attach",
    session: sessionName,
    cols: term.cols,
    rows: term.rows
  });
}
function handleDecryptedMessage(plaintext) {
  if (!sessionAttached) {
    try {
      const msg = JSON.parse(new TextDecoder().decode(plaintext));
      if (msg.type === "approved" && msg.client_token) {
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
        showView("terminal");
        if (!term) {
          term = new Terminal({
            cursorBlink: true,
            fontSize: 14,
            smoothScrollDuration: 80,
            theme: { background: "#0a0a0a" }
          });
          fitAddon = new FitAddon();
          term.loadAddon(fitAddon);
          term.open(terminalContainer);
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
        }
        return;
      } else if (msg.type === "sessions") {
        renderSessionList(msg.sessions);
        return;
      } else if (msg.type === "error") {
        showStatus(`Error: ${msg.message}`);
        return;
      }
    } catch {
    }
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
        const code = pkt.payload.length >= 4 ? new DataView(pkt.payload.buffer, pkt.payload.byteOffset).getInt32(0, false) : -1;
        showStatus(`Session exited (code ${code})`);
        disconnect();
        break;
      }
    }
  }
}
function spawnSession(name, cwd) {
  showStatus("Starting session...");
  const msg = { type: "spawn", name };
  if (cwd) msg.cwd = cwd;
  sendJson(msg);
}
function shortenCwd(cwd) {
  const home = "/Users/";
  if (cwd.startsWith(home)) {
    const after = cwd.slice(home.length).split("/");
    if (after.length > 1) return "~/" + after.slice(1).join("/");
  }
  const parts = cwd.split("/").filter(Boolean);
  if (parts.length > 2) return "\u2026/" + parts.slice(-2).join("/");
  return cwd;
}
function formatTags(tags) {
  if (!tags) return { inline: "", full: "", hasMore: false };
  const entries = Object.entries(tags);
  if (entries.length === 0) return { inline: "", full: "", hasMore: false };
  const fmt = (k, v) => v && v !== "true" ? `#${k}=${v}` : `#${k}`;
  const all = entries.map(([k, v]) => fmt(k, v));
  const MAX_INLINE = 3;
  if (all.length <= MAX_INLINE) {
    return { inline: all.join(" "), full: all.join(" "), hasMore: false };
  }
  return {
    inline: all.slice(0, MAX_INLINE).join(" ") + ` +${all.length - MAX_INLINE}`,
    full: all.join(" "),
    hasMore: true
  };
}
function renderSessionList(sessions) {
  sessionsContainer.innerHTML = "";
  const header = document.createElement("div");
  header.className = "session-list-header";
  header.innerHTML = `<span>name</span><span>cmd</span><span>cwd</span><span>tags</span>`;
  sessionsContainer.appendChild(header);
  if (sessions.length === 0) {
    const empty = document.createElement("div");
    empty.className = "session-row empty";
    empty.textContent = "no running sessions";
    sessionsContainer.appendChild(empty);
  } else {
    for (const s of sessions) {
      const row = document.createElement("div");
      row.className = "session-row";
      const name = s.displayName || s.name;
      const cmd = s.command || "";
      const cwd = s.cwd ? shortenCwd(s.cwd) : "";
      const tags = formatTags(s.tags);
      const tagsHtml = tags.hasMore ? `<span class="tag-inline">${escHtml(tags.inline.replace(/ \+\d+$/, ""))}</span> <span class="tag-more" data-full="${escHtml(tags.full)}">+${tags.full.split(" ").length - 3}</span>` : `<span>${escHtml(tags.inline)}</span>`;
      row.innerHTML = `<span class="col col-name" title="${escHtml(s.name)}">${escHtml(name)}</span><span class="col col-cmd" title="${escHtml(cmd)}">${escHtml(cmd)}</span><span class="col col-cwd" title="${escHtml(s.cwd || "")}">${escHtml(cwd)}</span><span class="col col-tags">${tagsHtml}</span>`;
      row.addEventListener("click", (e) => {
        const target = e.target;
        if (target.classList.contains("tag-more")) {
          e.stopPropagation();
          row.classList.toggle("expanded");
          const tagsCell = row.querySelector(".col-tags");
          if (tagsCell) tagsCell.textContent = tags.full;
          return;
        }
        const cols = Math.floor(terminalContainer.clientWidth / 9) || 80;
        const rows = Math.floor(terminalContainer.clientHeight / 17) || 24;
        attachToSession(s.name, cols, rows);
      });
      sessionsContainer.appendChild(row);
    }
  }
  const newRow = document.createElement("div");
  newRow.className = "session-row";
  newRow.innerHTML = `<span class="new-session-cta">+ new session</span>`;
  newRow.addEventListener("click", () => {
    const name = prompt("Session name:", `shell-${Date.now() % 1e4}`);
    if (!name) return;
    const cwd = prompt("Working directory:", "~");
    spawnSession(name.trim(), cwd && cwd !== "~" ? cwd : void 0);
  });
  sessionsContainer.appendChild(newRow);
  showView("sessions");
}
function escHtml(s) {
  const el = document.createElement("span");
  el.textContent = s;
  return el.innerHTML;
}
detachBtn.addEventListener("click", () => {
  if (sessionAttached) sendPtyPacket(makeDetach());
  sessionAttached = false;
  currentSession = null;
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
var quickBar = document.getElementById("quick-bar");
var keyPanel = document.getElementById("key-panel");
var textInputBar = document.getElementById("text-input-bar");
var textInput = document.getElementById("text-input");
var textSendBtn = document.getElementById("text-send-btn");
var textBackBtn = document.getElementById("text-back-btn");
var kbReopen = document.getElementById("kb-reopen");
var keyboard = document.getElementById("keyboard");
var stickyCtrl = false;
var lockedCtrl = false;
var lastCtrlTap = 0;
var stickyAlt = false;
var lockedAlt = false;
var lastAltTap = 0;
var kbMode = "bar";
function preventFocusSteal(e) {
  e.preventDefault();
}
function sendKey(initial) {
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
function toggleModifier(which) {
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
var ctrlBtn;
var altBtn;
function updateModifierButtons() {
  if (ctrlBtn) {
    ctrlBtn.className = "kb-btn" + (lockedCtrl ? " locked" : stickyCtrl ? " active" : "");
  }
  if (altBtn) {
    altBtn.className = "kb-btn" + (lockedAlt ? " locked" : stickyAlt ? " active" : "");
  }
}
function setKbMode(mode) {
  kbMode = mode;
  quickBar.style.display = mode === "bar" ? "flex" : "none";
  keyPanel.style.display = mode === "panel" ? "grid" : "none";
  textInputBar.style.display = mode === "text" ? "flex" : "none";
  keyboard.style.display = mode === "hidden" ? "none" : "";
  kbReopen.style.display = mode === "hidden" ? "block" : "none";
  if (mode === "panel") document.activeElement?.blur();
  if (mode === "text") textInput.focus();
  if (mode === "bar" && term) term.focus();
  updateVh();
}
function buildQuickBar() {
  const keys = [
    { label: "Txt", action: () => setKbMode("text") },
    { label: "Esc", seq: "\x1B" },
    { label: "Tab", seq: "	" },
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
    { label: "\u2715", action: () => setKbMode("hidden") }
  ];
  for (const k of keys) {
    const btn = document.createElement("button");
    btn.className = "kb-btn";
    btn.textContent = k.label;
    btn.addEventListener("mousedown", preventFocusSteal);
    if (k.seq) btn.addEventListener("click", () => sendKey(k.seq));
    else if (k.action) btn.addEventListener("click", k.action);
    if (k.id === "ctrl") ctrlBtn = btn;
    if (k.id === "alt") altBtn = btn;
    quickBar.appendChild(btn);
  }
}
function buildKeyPanel() {
  const keys = [
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
        } catch {
        }
      }
    }
  ];
  for (const k of keys) {
    const btn = document.createElement("button");
    btn.className = "kb-btn";
    btn.textContent = k.label;
    btn.addEventListener("mousedown", preventFocusSteal);
    if (k.seq) btn.addEventListener("click", () => sendKey(k.seq));
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
textInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    textSendBtn.click();
  }
});
textBackBtn.addEventListener("click", () => setKbMode("bar"));
kbReopen.addEventListener("click", () => setKbMode("bar"));
buildQuickBar();
buildKeyPanel();
var touchStartY = 0;
var scrollPixelOffset = 0;
var touchVelocity = 0;
var lastTouchY = 0;
var lastTouchTime = 0;
var inertiaFrame = null;
function getLineHeight() {
  if (term) {
    const canvas = terminalContainer.querySelector("canvas");
    if (canvas) return canvas.clientHeight / term.rows;
  }
  return 14 * 1.2;
}
function scrollByPixels(dy) {
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
  (e) => {
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
  (e) => {
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
    function inertia(now) {
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
var token = null;
var currentSession = null;
var reconnectTimer = null;
var reconnectDelay = 1e3;
var intentionalDisconnect = false;
function scheduleReconnect() {
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
function connectToRelay() {
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
    let wsUrl = `${scheme}://${token.host}/ws?role=client&secret_hash=${secretHash}`;
    if (token.clientToken) {
      wsUrl += `&client_token=${encodeURIComponent(token.clientToken)}`;
    }
    ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";
    window.__ptyRelayWs = ws;
    ws.onopen = () => {
      showStatus("Waiting for daemon...");
    };
    ws.onmessage = (event) => {
      if (typeof event.data === "string") {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "paired") {
            showStatus("Handshaking...");
            ws.send(handshake.hello);
          } else if (msg.type === "waiting_for_approval") {
            showStatus("Waiting for operator approval...");
          } else if (msg.type === "draining") {
            showStatus("Server updating...");
          } else if (msg.type === "peer_disconnected") {
            showStatus("Daemon disconnected");
            scheduleReconnect();
          } else if (msg.type === "error") {
            if (/token revoked/i.test(msg.message || "") && token && token.clientToken) {
              deleteStoredClientToken(token.host, token.publicKeyB64);
              showStatus("Access was revoked \u2014 reloading...");
              setTimeout(() => window.location.reload(), 800);
            } else {
              showStatus(`Error: ${msg.message}`);
            }
          }
        } catch {
        }
      } else {
        const data = new Uint8Array(event.data);
        if (!handshakeComplete) {
          try {
            transport = handshake.readWelcome(data);
            handshakeComplete = true;
            reconnectDelay = 1e3;
            sendJson({
              type: "hello",
              client: "web",
              os: navigator.userAgentData?.platform || navigator.platform || "unknown",
              label: navigator.userAgent.split(" ").pop() || "browser"
            });
            const sessionToAttach = currentSession || token.session;
            if (sessionToAttach) {
              const cols = term?.cols || Math.floor(terminalContainer.clientWidth / 9) || 80;
              const rows = term?.rows || Math.floor(terminalContainer.clientHeight / 17) || 24;
              attachToSession(sessionToAttach, cols, rows);
            } else {
              showStatus("Loading sessions...");
              sendJson({ type: "list" });
            }
          } catch (err) {
            showStatus(`Handshake failed: ${err.message}`);
            scheduleReconnect();
          }
        } else if (transport) {
          try {
            const plaintext = transport.decrypt(data);
            handleDecryptedMessage(plaintext);
          } catch (err) {
            showStatus(`Decryption failed: ${err.message}`);
            scheduleReconnect();
          }
        }
      }
    };
    ws.onerror = () => {
    };
    ws.onclose = (event) => {
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
async function main() {
  await sodium.ready;
  token = parseToken();
  if (!token) {
    showStatus("Invalid token URL. Expected: https://host/session#key.secret");
    return;
  }
  connectToRelay();
}
main();
