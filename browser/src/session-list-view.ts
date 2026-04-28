/**
 * Stateful renderer for the overview "session list" view.
 *
 * Why a factory + update() rather than a one-shot render(): the view
 * owns a filter <input> whose focus + caret position must survive
 * across re-renders. A function that does container.replaceChildren()
 * on every render would clobber that. The factory mounts the
 * skeleton (filter input, sort controls, header, rows container,
 * "+ new session" CTA) ONCE and only mutates the rows container on
 * update().
 *
 * Fuzzy matching is delegated to pty's TUI matcher so the web UI's
 * filter behaves identically to the interactive `pty` picker — same
 * boundary bonus, same consecutive-run bonus, same prefix bonus.
 * Imported via the npm-linked relative path (same pattern used in
 * integration/web.spec.ts to import pty's testing helpers).
 *
 * No DOM lookups, no daemon coupling — caller hands in a target
 * container and a couple of callbacks. Visual styling lives in
 * browser/src/index.html (CSS); this module only emits class hooks.
 */
import { fuzzyMatch as ptyFuzzyMatch } from "../../../pty/src/tui/fuzzy.ts";

export interface SessionMeta {
  name: string;
  status?: string;
  displayName?: string;
  command?: string;
  cwd?: string;
  tags?: Record<string, string>;
}

export interface RenderCallbacks {
  onAttach: (name: string) => void;
  onSpawn: () => void;
}

export interface SessionListView {
  /** Replace the source list. Filter + sort are applied on top. */
  update(sessions: SessionMeta[]): void;
  /** Move keyboard focus to the filter input. */
  focus(): void;
  /** Remove window-level event listeners; use only if you intend to
   *  destroy and recreate the view. Normal use never calls this. */
  destroy(): void;
}

type SortKey = "name" | "cmd" | "cwd";
type SortDir = "asc" | "desc";

/** Show ~/foo for paths under HOME, otherwise show the last 2 segments
 *  preceded by an ellipsis. Long absolute cwds are unreadable in a
 *  fixed column; this preserves the most useful tail. Exported for
 *  testability — its branches are non-trivial. */
export function shortenCwd(cwd: string): string {
  // Best-effort: we don't get HOME from the daemon, so we hard-code
  // the macOS pattern. If we ever need to support /home/<user> we'll
  // pass the prefix in from the caller.
  const home = "/Users/";
  if (cwd.startsWith(home)) {
    const after = cwd.slice(home.length).split("/");
    if (after.length > 1) return "~/" + after.slice(1).join("/");
  }
  const parts = cwd.split("/").filter(Boolean);
  if (parts.length > 2) return "…/" + parts.slice(-2).join("/");
  return cwd;
}

/** Format a tag map as space-joined `#key` / `#key=value` strings,
 *  collapsing to "+N" when there are more than MAX_INLINE entries. */
export function formatTags(tags: Record<string, string> | undefined): {
  inline: string;
  full: string;
  hasMore: boolean;
  total: number;
} {
  if (!tags) return { inline: "", full: "", hasMore: false, total: 0 };
  const entries = Object.entries(tags);
  if (entries.length === 0) return { inline: "", full: "", hasMore: false, total: 0 };
  const fmt = (k: string, v: string) =>
    v && v !== "true" ? `#${k}=${v}` : `#${k}`;
  const all = entries.map(([k, v]) => fmt(k, v));
  const MAX_INLINE = 3;
  if (all.length <= MAX_INLINE) {
    return { inline: all.join(" "), full: all.join(" "), hasMore: false, total: all.length };
  }
  return {
    inline: all.slice(0, MAX_INLINE).join(" "),
    full: all.join(" "),
    hasMore: true,
    total: all.length,
  };
}

/** Re-export pty's matcher under the same name so tests in this repo
 *  can import either source. Behavior is identical — same algorithm,
 *  same scoring. */
export const fuzzyMatch = ptyFuzzyMatch;

/** Score a session against a query. Returns the BEST score across the
 *  fields we want to match — name (with displayName as alternate),
 *  command, cwd, and each tag-key / tag-value individually. Matching
 *  per-field rather than against a flattened blob means a query that
 *  hits a single tag isn't penalized by the length of the
 *  concatenated other fields. */
function scoreSession(query: string, s: SessionMeta): { match: boolean; score: number } {
  if (!query) return { match: true, score: 0 };
  const fields: string[] = [s.name, s.command || "", s.cwd || ""];
  if (s.displayName) fields.push(s.displayName);
  if (s.tags) {
    for (const [k, v] of Object.entries(s.tags)) {
      fields.push(k);
      if (v) fields.push(v);
    }
  }
  let best: { match: boolean; score: number } = { match: false, score: 0 };
  for (const f of fields) {
    if (!f) continue;
    const r = ptyFuzzyMatch(query, f);
    if (r.match && r.score > best.score) best = r;
  }
  return best;
}

export function createSessionListView(
  container: HTMLElement,
  callbacks: RenderCallbacks
): SessionListView {
  const state = {
    sessions: [] as SessionMeta[],
    filter: "",
    sortKey: "name" as SortKey,
    sortDir: "asc" as SortDir,
  };

  // ─── Static skeleton: built once, never replaced. ───
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
  filterInput.placeholder = "filter…";
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

  const sortButtons: Record<SortKey, HTMLButtonElement> = {
    name: makeSortButton("name"),
    cmd: makeSortButton("cmd"),
    cwd: makeSortButton("cwd"),
  };
  function makeSortButton(key: SortKey): HTMLButtonElement {
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
  for (const key of ["name", "cmd", "cwd"] as SortKey[]) {
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

  // ─── Dynamic event wiring ───
  filterInput.addEventListener("input", () => {
    state.filter = filterInput.value;
    renderRows();
  });
  filterInput.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (filterInput.value) {
        // First Escape: clear the filter but keep focus.
        filterInput.value = "";
        state.filter = "";
        renderRows();
      } else {
        // Second Escape: blur, hand focus back to whatever was implicit.
        filterInput.blur();
      }
    }
  });

  // Type-to-filter: when the overview is on screen and focus has
  // drifted (e.g. just came back from a detach), grab printable
  // keystrokes from the window and route them to the filter input.
  // We don't preventDefault — letting the keystroke land in the input
  // naturally is what makes "just start typing" feel right.
  const onWindowKeydown = (e: KeyboardEvent) => {
    // Only when the overview container is visible.
    if (container.offsetParent === null) return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    // Only single-character printable keys (skip Tab, Enter, Esc, F-keys, arrows).
    if (e.key.length !== 1) return;
    // If the user is already typing in an input/textarea/contenteditable
    // (including the filter itself), let the event flow normally.
    const active = document.activeElement;
    if (
      active &&
      (active.tagName === "INPUT" ||
        active.tagName === "TEXTAREA" ||
        (active as HTMLElement).isContentEditable)
    ) {
      return;
    }
    filterInput.focus();
  };
  window.addEventListener("keydown", onWindowKeydown);

  // ─── Rendering ───
  function compareSessions(a: SessionMeta, b: SessionMeta): number {
    const get = (s: SessionMeta) => {
      if (state.sortKey === "name") return (s.displayName || s.name).toLowerCase();
      if (state.sortKey === "cmd") return (s.command || "").toLowerCase();
      return (s.cwd || "").toLowerCase();
    };
    const av = get(a);
    const bv = get(b);
    const cmp = av < bv ? -1 : av > bv ? 1 : 0;
    return state.sortDir === "asc" ? cmp : -cmp;
  }

  function applyFilterAndSort(): SessionMeta[] {
    if (state.filter) {
      // When filtering, rank by fuzzy score (best match first) — the
      // user's chosen sort key is a secondary tiebreaker. Filtering by
      // score is more useful than alphabetical here: the query is the
      // signal of what the user is looking for.
      const scored = state.sessions
        .map((s) => ({ s, score: scoreSession(state.filter, s) }))
        .filter((entry) => entry.score.match);
      scored.sort((a, b) => {
        if (b.score.score !== a.score.score) return b.score.score - a.score.score;
        return compareSessions(a.s, b.s);
      });
      return scored.map((entry) => entry.s);
    }
    return state.sessions.slice().sort(compareSessions);
  }

  function paintSortButtons(): void {
    for (const key of Object.keys(sortButtons) as SortKey[]) {
      const btn = sortButtons[key];
      const active = state.sortKey === key;
      btn.classList.toggle("active", active);
      const arrow = active ? (state.sortDir === "asc" ? "↑" : "↓") : "";
      btn.textContent = arrow ? `${key}${arrow}` : key;
    }
  }

  function renderRows(): void {
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
    update(sessions: SessionMeta[]) {
      state.sessions = sessions;
      renderRows();
    },
    focus() {
      filterInput.focus();
    },
    destroy() {
      window.removeEventListener("keydown", onWindowKeydown);
    },
  };
}

function buildSessionRow(
  s: SessionMeta,
  callbacks: RenderCallbacks
): HTMLElement {
  const row = document.createElement("div");
  row.className = "session-row";

  const name = s.displayName || s.name;
  const cmd = s.command || "";
  const cwdShort = s.cwd ? shortenCwd(s.cwd) : "";
  const tags = formatTags(s.tags);

  // Build cells using textContent so we don't need an explicit escape
  // pass — DOM APIs handle untrusted strings safely.
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

  // Click on .tag-more expands the row inline; clicks elsewhere on
  // the row attach to the session.
  row.addEventListener("click", (e) => {
    const target = e.target as HTMLElement;
    if (target.classList.contains("tag-more")) {
      e.stopPropagation();
      const expanded = row.classList.toggle("expanded");
      const tagsEl = row.querySelector(".col-tags") as HTMLElement | null;
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

function makeCol(extraClass: string, text: string): HTMLElement {
  const el = document.createElement("span");
  el.className = `col ${extraClass}`;
  el.textContent = text;
  return el;
}
