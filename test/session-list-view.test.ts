// @vitest-environment happy-dom
/**
 * Unit tests for the overview-list view. happy-dom provides a real
 * Document, so the factory mounts its skeleton and we drive update()
 * + simulate input/click events to verify behavior.
 *
 * Coverage focus: structure, escape behavior, click semantics, the
 * +N expand/collapse, and the new filter/sort interactions. Visual
 * density still needs Playwright screenshots — these tests don't try
 * to substitute for that.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  createSessionListView,
  shortenCwd,
  formatTags,
  fuzzyMatch,
  type SessionListView,
  type SessionMeta,
} from "../browser/src/session-list-view.ts";

function mountContainer(): HTMLElement {
  const c = document.createElement("div");
  c.id = "sessions-container";
  document.body.appendChild(c);
  return c;
}

let view: SessionListView | null = null;
function makeView(
  container: HTMLElement,
  callbacks: { onAttach?: (n: string) => void; onSpawn?: () => void } = {}
): SessionListView {
  view = createSessionListView(container, {
    onAttach: callbacks.onAttach ?? (() => {}),
    onSpawn: callbacks.onSpawn ?? (() => {}),
  });
  return view;
}

beforeEach(() => {
  document.body.replaceChildren();
});

afterEach(() => {
  view?.destroy();
  view = null;
});

describe("shortenCwd", () => {
  it("rewrites paths under /Users/<name>/ to ~/...", () => {
    expect(shortenCwd("/Users/myobie/src/foo")).toBe("~/src/foo");
  });

  it("truncates absolute paths outside /Users with ellipsis + last 2 segments", () => {
    expect(shortenCwd("/var/log/nginx/error.log")).toBe("…/nginx/error.log");
  });

  it("returns short paths verbatim", () => {
    expect(shortenCwd("/etc")).toBe("/etc");
    expect(shortenCwd("/var/log")).toBe("/var/log");
  });
});

describe("formatTags", () => {
  it("returns empty for undefined and {}", () => {
    expect(formatTags(undefined)).toEqual({ inline: "", full: "", hasMore: false, total: 0 });
    expect(formatTags({})).toEqual({ inline: "", full: "", hasMore: false, total: 0 });
  });

  it("uses #key shorthand for empty/'true' values, #key=value otherwise", () => {
    expect(formatTags({ ai: "true", env: "" }).inline).toBe("#ai #env");
    expect(formatTags({ env: "prod" }).inline).toBe("#env=prod");
  });

  it("collapses to inline + 'hasMore' when there are more than 3 tags", () => {
    const f = formatTags({ a: "1", b: "2", c: "3", d: "4", e: "5" });
    expect(f).toEqual({
      inline: "#a=1 #b=2 #c=3",
      full: "#a=1 #b=2 #c=3 #d=4 #e=5",
      hasMore: true,
      total: 5,
    });
  });
});

describe("fuzzyMatch (delegated to pty's matcher)", () => {
  it("subsequence match returns match=true with score > 0", () => {
    const r = fuzzyMatch("abc", "alphabetic");
    expect(r.match).toBe(true);
    expect(r.score).toBeGreaterThan(0);
  });

  it("non-match returns match=false", () => {
    expect(fuzzyMatch("xyz", "alphabetic")).toEqual({ match: false, score: 0 });
  });

  it("empty query matches everything", () => {
    expect(fuzzyMatch("", "anything").match).toBe(true);
  });

  it("prefix matches score higher than mid-string matches", () => {
    const prefix = fuzzyMatch("foo", "foobar");
    const middle = fuzzyMatch("foo", "xfoobar");
    expect(prefix.score).toBeGreaterThan(middle.score);
  });
});

describe("structure", () => {
  it("mounts toolbar (filter + sort) + header + rows + new-session CTA", () => {
    const c = mountContainer();
    makeView(c);
    expect(c.querySelector(".session-list-toolbar")).toBeTruthy();
    expect(c.querySelector(".filter-input")).toBeTruthy();
    expect(c.querySelectorAll(".sort-btn")).toHaveLength(3);
    expect(c.querySelector(".session-list-header")).toBeTruthy();
    expect(c.querySelector(".session-rows")).toBeTruthy();
    expect(c.querySelector(".new-session-cta")?.textContent).toBe("+ new session");
  });

  it("update() renders one row per session", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([{ name: "s1" }, { name: "s2" }, { name: "s3" }]);
    expect(c.querySelectorAll(".session-rows .session-row")).toHaveLength(3);
  });

  it("empty list renders the empty-state row inside .session-rows", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([]);
    const empty = c.querySelector(".session-rows .session-row.empty");
    expect(empty?.textContent).toBe("no running sessions");
  });

  it("each row has all four columns with the right contents", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([{ name: "s", command: "bash", cwd: "/Users/me/x", tags: { env: "dev" } }]);
    const row = c.querySelector(".session-rows .session-row");
    expect(row?.querySelector(".col-name")?.textContent).toBe("s");
    expect(row?.querySelector(".col-cmd")?.textContent).toBe("bash");
    expect(row?.querySelector(".col-cwd")?.textContent).toBe("~/x");
    expect(row?.querySelector(".col-tags")?.textContent).toBe("#env=dev");
  });

  it("displayName overrides name; title attr keeps the real name", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([{ name: "real", displayName: "Pretty" }]);
    const nameCell = c.querySelector(".col-name") as HTMLElement;
    expect(nameCell.textContent).toBe("Pretty");
    expect(nameCell.title).toBe("real");
  });

  it("does not interpret HTML in any user-provided field (XSS safe)", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([
      {
        name: "<img src=x onerror=alert(1)>",
        command: "<script>alert(2)</script>",
        cwd: "/Users/me/<x>",
        tags: { "<a>": "<b>" },
      },
    ]);
    expect(c.querySelector("img")).toBeNull();
    expect(c.querySelector("script")).toBeNull();
    expect(c.querySelector(".col-name")?.textContent).toBe("<img src=x onerror=alert(1)>");
  });
});

describe("filter", () => {
  function setFilter(c: HTMLElement, value: string) {
    const input = c.querySelector(".filter-input") as HTMLInputElement;
    input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }

  it("filters rows by fuzzy match on name", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([{ name: "claude-foo" }, { name: "build-watch" }, { name: "shell-1" }]);
    setFilter(c, "cld");
    const names = Array.from(c.querySelectorAll(".col-name")).map((e) => e.textContent);
    expect(names).toEqual(["claude-foo"]);
  });

  it("matches across cmd, cwd, and tag keys/values", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([
      { name: "a", command: "claude --resume" },
      { name: "b", cwd: "/Users/me/important-thing" },
      { name: "c", tags: { project: "the-thing" } },
    ]);
    setFilter(c, "thing");
    const names = Array.from(c.querySelectorAll(".col-name")).map((e) => e.textContent);
    // Should match b (cwd) and c (tag value); ordering by score may
    // vary, so assert as a set.
    expect(new Set(names)).toEqual(new Set(["b", "c"]));
  });

  it("ranks results by fuzzy score, best match first", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([
      { name: "ax" },                  // weak match
      { name: "abc" },                 // strong match (prefix + consecutive)
      { name: "alphabetic" },          // weaker than abc
    ]);
    setFilter(c, "abc");
    const names = Array.from(c.querySelectorAll(".col-name")).map((e) => e.textContent);
    expect(names[0]).toBe("abc"); // best match ranks first
  });

  it("shows a 'no matches' empty state when filter matches nothing", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([{ name: "shell" }]);
    setFilter(c, "zzz-nope");
    const empty = c.querySelector(".session-rows .session-row.empty");
    expect(empty?.textContent).toContain("zzz-nope");
  });

  it("Escape on the filter input clears the value (first press)", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([{ name: "shell" }]);
    setFilter(c, "shell");
    const input = c.querySelector(".filter-input") as HTMLInputElement;
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(input.value).toBe("");
  });
});

describe("sort", () => {
  function getRowNames(c: HTMLElement): string[] {
    return Array.from(c.querySelectorAll(".col-name")).map((e) => e.textContent || "");
  }

  it("default sort is name ascending", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([{ name: "c" }, { name: "a" }, { name: "b" }]);
    expect(getRowNames(c)).toEqual(["a", "b", "c"]);
  });

  it("clicking the active sort button toggles asc/desc", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([{ name: "a" }, { name: "b" }, { name: "c" }]);
    const nameBtn = c.querySelector('.sort-btn[data-key="name"]') as HTMLButtonElement;
    nameBtn.click(); // already-active key toggles to desc
    expect(getRowNames(c)).toEqual(["c", "b", "a"]);
    nameBtn.click(); // back to asc
    expect(getRowNames(c)).toEqual(["a", "b", "c"]);
  });

  it("clicking a different sort button switches the key", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([
      { name: "z", command: "alpha" },
      { name: "a", command: "zeta" },
    ]);
    const cmdBtn = c.querySelector('.sort-btn[data-key="cmd"]') as HTMLButtonElement;
    cmdBtn.click();
    // sort key flipped to "cmd", direction reset to asc
    expect(getRowNames(c)).toEqual(["z", "a"]); // alpha < zeta
  });

  it("active sort button gets .active class and the arrow indicator", () => {
    const c = mountContainer();
    makeView(c);
    const nameBtn = c.querySelector('.sort-btn[data-key="name"]') as HTMLButtonElement;
    expect(nameBtn.classList.contains("active")).toBe(true);
    expect(nameBtn.textContent).toMatch(/name[↑↓]/);
  });
});

describe("interactions", () => {
  it("clicking a session row calls onAttach with the session name", () => {
    const c = mountContainer();
    const onAttach = vi.fn();
    const v = makeView(c, { onAttach });
    v.update([{ name: "demo" }]);
    (c.querySelector(".session-rows .col-name") as HTMLElement).click();
    expect(onAttach).toHaveBeenCalledWith("demo");
  });

  it("clicking the new-session CTA calls onSpawn", () => {
    const c = mountContainer();
    const onSpawn = vi.fn();
    makeView(c, { onSpawn });
    (c.querySelector(".new-session-cta") as HTMLElement).click();
    expect(onSpawn).toHaveBeenCalledTimes(1);
  });

  it("clicking the +N tag-more pill expands the row and does NOT trigger onAttach", () => {
    const c = mountContainer();
    const onAttach = vi.fn();
    const v = makeView(c, { onAttach });
    v.update([{ name: "x", tags: { a: "1", b: "2", c: "3", d: "4" } }]);
    const row = c.querySelector(".session-rows .session-row") as HTMLElement;
    const more = row.querySelector(".tag-more") as HTMLElement;
    more.click();
    expect(row.classList.contains("expanded")).toBe(true);
    expect(onAttach).not.toHaveBeenCalled();
    expect(row.querySelector(".col-tags")?.textContent).toBe("#a=1 #b=2 #c=3 #d=4");
  });

  it("update() preserves filter input focus across calls", () => {
    const c = mountContainer();
    const v = makeView(c);
    v.update([{ name: "a" }]);
    const input = c.querySelector(".filter-input") as HTMLInputElement;
    input.focus();
    expect(document.activeElement).toBe(input);
    v.update([{ name: "a" }, { name: "b" }]);
    // The input was mounted ONCE in the skeleton — its focus should
    // survive the rows-only re-render.
    expect(document.activeElement).toBe(input);
  });
});
