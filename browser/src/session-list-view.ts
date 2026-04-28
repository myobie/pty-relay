/**
 * Pure-ish renderer for the overview "session list" view. Extracted
 * from main.ts so it can be unit-tested in jsdom/happy-dom without
 * booting the daemon.
 *
 * The renderer takes a target container element and a set of callbacks
 * (attach a session, spawn a new session). It writes DOM into the
 * container — header row, one row per session, "+ new session" CTA.
 * No module-scope DOM lookups, no daemon dependency, no globals.
 *
 * Visual styling lives in browser/src/index.html (CSS); this module
 * only emits class hooks (.session-row / .col / .col-name etc.).
 */

export interface SessionMeta {
  name: string;
  status?: string;
  displayName?: string;
  command?: string;
  cwd?: string;
  tags?: Record<string, string>;
}

export interface RenderCallbacks {
  /** User clicked a session row. */
  onAttach: (name: string) => void;
  /** User clicked the "+ new session" CTA. */
  onSpawn: () => void;
}

/** Show ~/foo for paths under HOME, otherwise show the last 2 segments
 *  preceded by an ellipsis. Long absolute cwds are unreadable in a
 *  fixed column; this preserves the most useful tail. Exported for
 *  test-ability — its branches are non-trivial. */
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

/** Format a tag map as a space-joined `#key` / `#key=value` string,
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

/** Render the entire session list view into `container`. Replaces any
 *  existing children. Side effects are limited to the container's
 *  subtree. */
export function renderSessionList(
  container: HTMLElement,
  sessions: SessionMeta[],
  callbacks: RenderCallbacks
): void {
  container.replaceChildren();

  // Column header — TUI-style, four fixed columns. Doesn't get a row
  // click handler (it's not a session).
  const header = document.createElement("div");
  header.className = "session-list-header";
  for (const label of ["name", "cmd", "cwd", "tags"]) {
    const span = document.createElement("span");
    span.textContent = label;
    header.appendChild(span);
  }
  container.appendChild(header);

  if (sessions.length === 0) {
    const empty = document.createElement("div");
    empty.className = "session-row empty";
    empty.textContent = "no running sessions";
    container.appendChild(empty);
  } else {
    for (const s of sessions) {
      container.appendChild(buildSessionRow(s, callbacks));
    }
  }

  // "+ new session" goes BELOW the listing — it's an action, not data.
  const newRow = document.createElement("div");
  newRow.className = "session-row new-session-row";
  const cta = document.createElement("span");
  cta.className = "new-session-cta";
  cta.textContent = "+ new session";
  newRow.appendChild(cta);
  newRow.addEventListener("click", () => callbacks.onSpawn());
  container.appendChild(newRow);
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

  // Build cells using textContent rather than innerHTML so we don't
  // need an explicit escape pass — DOM APIs handle untrusted strings
  // safely, and the "title" attribute via .title= property does too.
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
          // Collapse back to the inline+more form.
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
