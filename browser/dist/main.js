// browser/src/main.ts
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import sodium from "libsodium-wrappers-sumo";

// ../pty/src/tui/fuzzy.ts
function fuzzyMatch(query, target) {
  if (query.length === 0) return { match: true, score: 1 };
  const q = query.toLowerCase();
  const t = target.toLowerCase();
  if (q.length > t.length) return { match: false, score: 0 };
  let qi = 0;
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) qi++;
  }
  if (qi < q.length) return { match: false, score: 0 };
  const matchPositions = findBestMatch(q, t);
  let score = 0;
  let consecutive = 0;
  for (let i = 0; i < matchPositions.length; i++) {
    if (i > 0 && matchPositions[i] === matchPositions[i - 1] + 1) {
      consecutive++;
      score += consecutive * 2;
    } else {
      consecutive = 0;
    }
  }
  for (const pos of matchPositions) {
    if (pos === 0 || isBoundary(t, pos)) {
      score += 3;
    }
  }
  if (matchPositions[0] === 0) {
    score += 5;
  }
  score += Math.max(0, 10 - (t.length - q.length));
  return { match: true, score };
}
function isBoundary(str, pos) {
  if (pos === 0) return true;
  const prev = str[pos - 1];
  return prev === "-" || prev === "_" || prev === "/" || prev === " " || prev === ".";
}
function findBestMatch(query, target) {
  const boundaryMatch = matchPreferBoundaries(query, target);
  if (boundaryMatch) return boundaryMatch;
  const positions = [];
  let qi = 0;
  for (let ti = 0; ti < target.length && qi < query.length; ti++) {
    if (target[ti] === query[qi]) {
      positions.push(ti);
      qi++;
    }
  }
  return positions;
}
function matchPreferBoundaries(query, target) {
  const positions = [];
  let qi = 0;
  let ti = 0;
  while (qi < query.length && ti < target.length) {
    let foundBoundary = false;
    for (let ahead = ti; ahead < target.length; ahead++) {
      if (target[ahead] === query[qi] && isBoundary(target, ahead)) {
        if (canMatch(query, qi + 1, target, ahead + 1)) {
          positions.push(ahead);
          qi++;
          ti = ahead + 1;
          foundBoundary = true;
          break;
        }
      }
    }
    if (!foundBoundary) {
      while (ti < target.length && target[ti] !== query[qi]) ti++;
      if (ti >= target.length) return null;
      positions.push(ti);
      qi++;
      ti++;
    }
  }
  return qi === query.length ? positions : null;
}
function canMatch(query, qi, target, ti) {
  while (qi < query.length && ti < target.length) {
    if (target[ti] === query[qi]) qi++;
    ti++;
  }
  return qi >= query.length;
}

// browser/src/session-list-view.ts
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
  if (!tags) return { inline: "", full: "", hasMore: false, total: 0 };
  const entries = Object.entries(tags);
  if (entries.length === 0) return { inline: "", full: "", hasMore: false, total: 0 };
  const fmt = (k, v) => v && v !== "true" ? `#${k}=${v}` : `#${k}`;
  const all = entries.map(([k, v]) => fmt(k, v));
  const MAX_INLINE = 3;
  if (all.length <= MAX_INLINE) {
    return { inline: all.join(" "), full: all.join(" "), hasMore: false, total: all.length };
  }
  return {
    inline: all.slice(0, MAX_INLINE).join(" "),
    full: all.join(" "),
    hasMore: true,
    total: all.length
  };
}
function scoreSession(query, s) {
  if (!query) return { match: true, score: 0 };
  const fields = [s.name, s.command || "", s.cwd || ""];
  if (s.displayName) fields.push(s.displayName);
  if (s.tags) {
    for (const [k, v] of Object.entries(s.tags)) {
      fields.push(k);
      if (v) fields.push(v);
    }
  }
  let best = { match: false, score: 0 };
  for (const f of fields) {
    if (!f) continue;
    const r = fuzzyMatch(query, f);
    if (r.match && r.score > best.score) best = r;
  }
  return best;
}
function createSessionListView(container, callbacks) {
  const state = {
    sessions: [],
    filter: "",
    sortKey: "name",
    sortDir: "asc"
  };
  container.replaceChildren();
  const toolbar = document.createElement("div");
  toolbar.className = "session-list-toolbar";
  const filterWrap = document.createElement("label");
  filterWrap.className = "filter-input-wrap";
  const filterPrompt = document.createElement("span");
  filterPrompt.className = "filter-prompt";
  filterPrompt.textContent = "/";
  const filterInput = document.createElement("input");
  filterInput.type = "text";
  filterInput.className = "filter-input";
  filterInput.placeholder = "filter\u2026";
  filterInput.spellcheck = false;
  filterInput.autocomplete = "off";
  filterInput.setAttribute("aria-label", "filter sessions");
  filterWrap.appendChild(filterPrompt);
  filterWrap.appendChild(filterInput);
  const sortWrap = document.createElement("div");
  sortWrap.className = "sort-controls";
  const sortLabel = document.createElement("span");
  sortLabel.className = "sort-label";
  sortLabel.textContent = "sort:";
  sortWrap.appendChild(sortLabel);
  const sortButtons = {
    name: makeSortButton("name"),
    cmd: makeSortButton("cmd"),
    cwd: makeSortButton("cwd")
  };
  function makeSortButton(key) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "sort-btn";
    btn.dataset.key = key;
    btn.addEventListener("click", () => {
      if (state.sortKey === key) {
        state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      } else {
        state.sortKey = key;
        state.sortDir = "asc";
      }
      renderRows();
      paintSortButtons();
    });
    return btn;
  }
  for (const key of ["name", "cmd", "cwd"]) {
    sortWrap.appendChild(sortButtons[key]);
  }
  toolbar.appendChild(filterWrap);
  toolbar.appendChild(sortWrap);
  container.appendChild(toolbar);
  const header = document.createElement("div");
  header.className = "session-list-header";
  for (const label of ["name", "cmd", "cwd", "tags"]) {
    const span = document.createElement("span");
    span.textContent = label;
    header.appendChild(span);
  }
  container.appendChild(header);
  const rowsContainer = document.createElement("div");
  rowsContainer.className = "session-rows";
  container.appendChild(rowsContainer);
  const newRow = document.createElement("div");
  newRow.className = "session-row new-session-row";
  const cta = document.createElement("span");
  cta.className = "new-session-cta";
  cta.textContent = "+ new session";
  newRow.appendChild(cta);
  newRow.addEventListener("click", () => callbacks.onSpawn());
  container.appendChild(newRow);
  filterInput.addEventListener("input", () => {
    state.filter = filterInput.value;
    renderRows();
  });
  filterInput.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (filterInput.value) {
        filterInput.value = "";
        state.filter = "";
        renderRows();
      } else {
        filterInput.blur();
      }
    }
  });
  const onWindowKeydown = (e) => {
    if (container.offsetParent === null) return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key.length !== 1) return;
    const active = document.activeElement;
    if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA" || active.isContentEditable)) {
      return;
    }
    filterInput.focus();
  };
  window.addEventListener("keydown", onWindowKeydown);
  function compareSessions(a, b) {
    const get = (s) => {
      if (state.sortKey === "name") return (s.displayName || s.name).toLowerCase();
      if (state.sortKey === "cmd") return (s.command || "").toLowerCase();
      return (s.cwd || "").toLowerCase();
    };
    const av = get(a);
    const bv = get(b);
    const cmp = av < bv ? -1 : av > bv ? 1 : 0;
    return state.sortDir === "asc" ? cmp : -cmp;
  }
  function applyFilterAndSort() {
    if (state.filter) {
      const scored = state.sessions.map((s) => ({ s, score: scoreSession(state.filter, s) })).filter((entry) => entry.score.match);
      scored.sort((a, b) => {
        if (b.score.score !== a.score.score) return b.score.score - a.score.score;
        return compareSessions(a.s, b.s);
      });
      return scored.map((entry) => entry.s);
    }
    return state.sessions.slice().sort(compareSessions);
  }
  function paintSortButtons() {
    for (const key of Object.keys(sortButtons)) {
      const btn = sortButtons[key];
      const active = state.sortKey === key;
      btn.classList.toggle("active", active);
      const arrow = active ? state.sortDir === "asc" ? "\u2191" : "\u2193" : "";
      btn.textContent = arrow ? `${key}${arrow}` : key;
    }
  }
  function renderRows() {
    const visible = applyFilterAndSort();
    rowsContainer.replaceChildren();
    if (state.sessions.length === 0) {
      const empty = document.createElement("div");
      empty.className = "session-row empty";
      empty.textContent = "no running sessions";
      rowsContainer.appendChild(empty);
      return;
    }
    if (visible.length === 0) {
      const empty = document.createElement("div");
      empty.className = "session-row empty";
      empty.textContent = `no sessions match "${state.filter}"`;
      rowsContainer.appendChild(empty);
      return;
    }
    for (const s of visible) {
      rowsContainer.appendChild(buildSessionRow(s, callbacks));
    }
  }
  paintSortButtons();
  return {
    update(sessions) {
      state.sessions = sessions;
      renderRows();
    },
    focus() {
      filterInput.focus();
    },
    destroy() {
      window.removeEventListener("keydown", onWindowKeydown);
    }
  };
}
function buildSessionRow(s, callbacks) {
  const row = document.createElement("div");
  row.className = "session-row";
  const name = s.displayName || s.name;
  const cmd = s.command || "";
  const cwdShort = s.cwd ? shortenCwd(s.cwd) : "";
  const tags = formatTags(s.tags);
  const nameCell = makeCol("col-name", name);
  nameCell.title = s.name;
  row.appendChild(nameCell);
  const cmdCell = makeCol("col-cmd", cmd);
  cmdCell.title = cmd;
  row.appendChild(cmdCell);
  const cwdCell = makeCol("col-cwd", cwdShort);
  cwdCell.title = s.cwd || "";
  row.appendChild(cwdCell);
  const tagsCell = document.createElement("span");
  tagsCell.className = "col col-tags";
  if (tags.hasMore) {
    const inline = document.createElement("span");
    inline.className = "tag-inline";
    inline.textContent = tags.inline;
    tagsCell.appendChild(inline);
    tagsCell.appendChild(document.createTextNode(" "));
    const more = document.createElement("span");
    more.className = "tag-more";
    more.textContent = `+${tags.total - 3}`;
    tagsCell.appendChild(more);
  } else {
    const single = document.createElement("span");
    single.textContent = tags.inline;
    tagsCell.appendChild(single);
  }
  row.appendChild(tagsCell);
  row.addEventListener("click", (e) => {
    const target = e.target;
    if (target.classList.contains("tag-more")) {
      e.stopPropagation();
      const expanded = row.classList.toggle("expanded");
      const tagsEl = row.querySelector(".col-tags");
      if (tagsEl) {
        if (expanded) {
          tagsEl.replaceChildren(document.createTextNode(tags.full));
        } else {
          tagsEl.replaceChildren();
          const inline = document.createElement("span");
          inline.className = "tag-inline";
          inline.textContent = tags.inline;
          tagsEl.appendChild(inline);
          tagsEl.appendChild(document.createTextNode(" "));
          const more = document.createElement("span");
          more.className = "tag-more";
          more.textContent = `+${tags.total - 3}`;
          tagsEl.appendChild(more);
        }
      }
      return;
    }
    callbacks.onAttach(s.name);
  });
  return row;
}
function makeCol(extraClass, text) {
  const el = document.createElement("span");
  el.className = `col ${extraClass}`;
  el.textContent = text;
  return el;
}

// browser/src/latency-stats.ts
var SAMPLE_CAP = 200;
var PENDING_CAP = 1e3;
var WS_FRAME_CAP = 200;
function createLatencyTracker(term2) {
  const pending = [];
  const samples = [];
  const wsArrivals = [];
  const wsSizes = [];
  let trackerStartedAt = performance.now();
  let trackerStartedAtMs = Date.now();
  const onDataDisposer = term2.onData((data) => {
    const now = performance.now();
    for (let i = 0; i < data.length; i++) {
      pending.push({ sentAt: now });
      if (pending.length > PENDING_CAP) pending.shift();
    }
  });
  function advanceRecv() {
    const entry = pending.find((p) => p.recvAt === void 0);
    if (entry) entry.recvAt = performance.now();
  }
  function advanceParsed() {
    const entry = pending.find(
      (p) => p.recvAt !== void 0 && p.parsedAt === void 0
    );
    if (entry) entry.parsedAt = performance.now();
  }
  function advanceRender() {
    const idx = pending.findIndex((p) => p.parsedAt !== void 0);
    if (idx === -1) return;
    const entry = pending[idx];
    pending.splice(idx, 1);
    const now = performance.now();
    samples.push({
      sentAt: round1(entry.sentAt - trackerStartedAt),
      // relative-to-window for compactness
      network: round1((entry.recvAt ?? now) - entry.sentAt),
      parse: round1((entry.parsedAt ?? now) - (entry.recvAt ?? now)),
      paint: round1(now - (entry.parsedAt ?? now)),
      total: round1(now - entry.sentAt)
    });
    if (samples.length > SAMPLE_CAP) samples.shift();
  }
  const onWriteParsedDisposer = term2.onWriteParsed(() => {
    advanceParsed();
  });
  const onRenderDisposer = term2.onRender(() => {
    advanceRender();
  });
  function statsFromArray(values) {
    if (values.length === 0) {
      return { count: 0, min: 0, median: 0, p95: 0, max: 0 };
    }
    const sorted = values.slice().sort((a, b) => a - b);
    const pct = (p) => sorted[Math.max(0, Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1))];
    return {
      count: values.length,
      min: round1(sorted[0]),
      median: round1(pct(0.5)),
      p95: round1(pct(0.95)),
      max: round1(sorted[sorted.length - 1])
    };
  }
  function summaryNow() {
    const totals = samples.map((s) => s.total);
    const stats = statsFromArray(totals);
    return {
      count: stats.count,
      pending: pending.length,
      min: stats.min,
      median: stats.median,
      p95: stats.p95,
      max: stats.max,
      windowSec: round1((performance.now() - trackerStartedAt) / 1e3)
    };
  }
  function keystrokeReportNow() {
    return {
      count: samples.length,
      pending: pending.length,
      windowSec: round1((performance.now() - trackerStartedAt) / 1e3),
      total: statsFromArray(samples.map((s) => s.total)),
      network: statsFromArray(samples.map((s) => s.network)),
      parse: statsFromArray(samples.map((s) => s.parse)),
      paint: statsFromArray(samples.map((s) => s.paint)),
      samples: samples.slice()
    };
  }
  function wsStatsNow() {
    const interArrival = [];
    for (let i = 1; i < wsArrivals.length; i++) {
      interArrival.push(round1(wsArrivals[i] - wsArrivals[i - 1]));
    }
    return {
      count: wsArrivals.length,
      sizes: wsSizes.slice(),
      interArrivalMs: interArrival
    };
  }
  return {
    summary: summaryNow,
    report() {
      return {
        startedAt: trackerStartedAtMs,
        endedAt: Date.now(),
        keystrokes: keystrokeReportNow(),
        ws: wsStatsNow()
      };
    },
    recordRecv(bytes) {
      const now = performance.now();
      wsArrivals.push(now);
      wsSizes.push(bytes);
      if (wsArrivals.length > WS_FRAME_CAP) {
        wsArrivals.shift();
        wsSizes.shift();
      }
      advanceRecv();
    },
    reset() {
      pending.length = 0;
      samples.length = 0;
      wsArrivals.length = 0;
      wsSizes.length = 0;
      trackerStartedAt = performance.now();
      trackerStartedAtMs = Date.now();
    },
    destroy() {
      onDataDisposer.dispose();
      onRenderDisposer.dispose();
      onWriteParsedDisposer.dispose();
    }
  };
}
function round1(n) {
  return Math.round(n * 10) / 10;
}
function formatSummary(s, context = {}) {
  const lines = [
    "pty-relay web latency",
    "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500",
    `samples: ${s.count}   pending: ${s.pending}   window: ${s.windowSec}s`
  ];
  if (s.count > 0) {
    lines.push(
      `min: ${s.min}ms   median: ${s.median}ms   p95: ${s.p95}ms   max: ${s.max}ms`
    );
  } else {
    lines.push("(no samples yet \u2014 type some characters into the terminal)");
  }
  if (context.ua) lines.push(`ua: ${context.ua}`);
  if (context.relay) lines.push(`relay: ${context.relay}`);
  if (context.viewportW && context.viewportH) {
    lines.push(`viewport: ${context.viewportW}\xD7${context.viewportH}`);
  }
  return lines.join("\n");
}
function formatCompact(s) {
  if (s.count === 0) return `n=0`;
  return `n=${s.count} p50=${s.median}ms p95=${s.p95}ms`;
}

// browser/src/main.ts
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
var sessionListEl = document.getElementById("session-list");
var terminalView = document.getElementById("terminal-view");
var sessionsContainer = document.getElementById("sessions-container");
var sessionNameLabel = document.getElementById("session-name-label");
var terminalContainer = document.getElementById("terminal-container");
var detachBtn = document.getElementById("detach-btn");
var statsBtn = document.getElementById("stats-btn");
var latencyStatEl = document.getElementById("latency-stat");
function showView(view) {
  statusOverlay.style.display = "none";
  sessionListEl.style.display = "none";
  terminalView.style.display = "none";
  if (view === "loading") statusOverlay.style.display = "flex";
  else if (view === "sessions") sessionListEl.style.display = "flex";
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
var DEFAULT_DOC_TITLE = "pty relay";
function setUrlSession(session) {
  const newPath = session ? `/${encodeURIComponent(session)}` : "/";
  history.replaceState(null, "", newPath + location.search + location.hash);
}
function bindTerminalTitle(t, fallbackName) {
  t.onTitleChange((title) => {
    document.title = title && title.length > 0 ? title : fallbackName;
  });
}
var latencyTracker = null;
var latencyTickHandle = null;
var latencyReportHandle = null;
var LATENCY_TICK_MS = 1e3;
var LATENCY_REPORT_INTERVAL_MS = 3e4;
function bindLatencyTracker(t) {
  if (latencyTracker) latencyTracker.destroy();
  latencyTracker = createLatencyTracker(t);
  if (latencyTickHandle) clearInterval(latencyTickHandle);
  latencyTickHandle = setInterval(() => {
    if (!latencyTracker) return;
    const s = latencyTracker.summary();
    latencyStatEl.textContent = formatCompact(s);
    latencyStatEl.classList.toggle("warn", s.count > 0 && s.median >= 60);
    latencyStatEl.classList.toggle("bad", s.count > 0 && s.median >= 120);
  }, LATENCY_TICK_MS);
  if (latencyReportHandle) clearInterval(latencyReportHandle);
  latencyReportHandle = setInterval(() => {
    if (!latencyTracker || !sessionAttached || !transport) return;
    const r = latencyTracker.report();
    if (r.keystrokes.count === 0 && r.ws.count === 0) return;
    const payload = {
      type: "latency_report",
      report: r,
      ua: navigator.userAgent,
      viewport: { w: window.innerWidth, h: window.innerHeight },
      relay: token ? `${location.protocol}//${token.host}` : null,
      session: currentSession
    };
    try {
      sendJson(payload);
      latencyTracker.reset();
    } catch {
    }
  }, LATENCY_REPORT_INTERVAL_MS);
}
function teardownLatencyTracker() {
  if (latencyTickHandle) {
    clearInterval(latencyTickHandle);
    latencyTickHandle = null;
  }
  if (latencyReportHandle) {
    clearInterval(latencyReportHandle);
    latencyReportHandle = null;
  }
  if (latencyTracker) {
    latencyTracker.destroy();
    latencyTracker = null;
  }
  latencyStatEl.textContent = "";
  latencyStatEl.classList.remove("warn", "bad");
}
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
  document.title = DEFAULT_DOC_TITLE;
  teardownLatencyTracker();
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
  setUrlSession(sessionName);
  document.title = sessionName;
  showView("terminal");
  if (!term) {
    term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      // smoothScrollDuration was 80ms — animating scrolls felt
      // sluggish for typing where every output line shifts the
      // viewport. 0 disables the animation; xterm renders at the
      // next RAF as before, but no easing layer on top.
      smoothScrollDuration: 0,
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
    bindTerminalTitle(term, sessionName);
    bindLatencyTracker(term);
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
        document.title = msg.session;
        setUrlSession(msg.session);
        showView("terminal");
        if (!term) {
          term = new Terminal({
            cursorBlink: true,
            fontSize: 14,
            // smoothScrollDuration was 80ms — animating scrolls felt
            // sluggish for typing where every output line shifts the
            // viewport. 0 disables the animation; xterm renders at the
            // next RAF as before, but no easing layer on top.
            smoothScrollDuration: 0,
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
          bindTerminalTitle(term, msg.session);
          bindLatencyTracker(term);
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
        setUrlSession(null);
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
var overviewView = null;
function renderSessionList(sessions) {
  if (!overviewView) {
    overviewView = createSessionListView(sessionsContainer, {
      onAttach: (name) => {
        const cols = Math.floor(terminalContainer.clientWidth / 9) || 80;
        const rows = Math.floor(terminalContainer.clientHeight / 17) || 24;
        attachToSession(name, cols, rows);
      },
      onSpawn: () => {
        const name = prompt("Session name:", `shell-${Date.now() % 1e4}`);
        if (!name) return;
        const cwd = prompt("Working directory:", "~");
        spawnSession(name.trim(), cwd && cwd !== "~" ? cwd : void 0);
      }
    });
  }
  overviewView.update(sessions);
  showView("sessions");
}
statsBtn.addEventListener("click", async () => {
  if (!latencyTracker) return;
  const summary = latencyTracker.summary();
  const text = formatSummary(summary, {
    ua: navigator.userAgent,
    relay: token ? `${location.protocol}//${token.host}` : void 0,
    viewportW: window.innerWidth,
    viewportH: window.innerHeight
  });
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    console.log(text);
  }
  statsBtn.classList.add("copied");
  setTimeout(() => statsBtn.classList.remove("copied"), 600);
});
detachBtn.addEventListener("click", () => {
  if (sessionAttached) sendPtyPacket(makeDetach());
  sessionAttached = false;
  currentSession = null;
  document.title = DEFAULT_DOC_TITLE;
  setUrlSession(null);
  packetParser = new PacketParser();
  teardownLatencyTracker();
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
        if (latencyTracker) latencyTracker.recordRecv(data.length);
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
      if (!intentionalDisconnect) {
        scheduleReconnect();
      }
    };
  });
}
function paintError(prefix, detail) {
  const el = document.getElementById("status-overlay");
  if (el) {
    el.style.display = "flex";
    el.style.whiteSpace = "pre-wrap";
    el.style.padding = "20px";
    el.style.fontSize = "12px";
    el.style.textAlign = "left";
    el.textContent = `${prefix}

${detail}`;
  }
}
window.addEventListener("error", (e) => {
  paintError(
    "JavaScript error \u2014 page failed to initialize",
    `${e.message}
${e.filename || ""}:${e.lineno || ""}:${e.colno || ""}`
  );
});
window.addEventListener("unhandledrejection", (e) => {
  const r = e.reason;
  paintError(
    "Promise rejection \u2014 page failed to initialize",
    typeof r === "string" ? r : r?.stack || r?.message || JSON.stringify(r)
  );
});
async function main() {
  showStatus("Initializing crypto\u2026");
  await sodium.ready;
  showStatus("Parsing token\u2026");
  token = parseToken();
  if (!token) {
    showStatus("Invalid token URL. Expected: https://host/session#key.secret");
    return;
  }
  showStatus(`Connecting to ${token.host}\u2026`);
  connectToRelay();
}
main().catch((err) => {
  paintError("main() crashed", String(err?.stack || err?.message || err));
});
