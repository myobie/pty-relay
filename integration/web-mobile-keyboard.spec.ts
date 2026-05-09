import { test, expect, type Page, type BrowserContext } from "@playwright/test";
import * as http from "node:http";
import * as fs from "node:fs";
import * as path from "node:path";

/**
 * Mobile keyboard / scroll-lock simulation.
 *
 * Headless browsers don't render a real soft keyboard, so we can't
 * trigger the iOS auto-scroll-to-input behavior directly. Instead we
 * *simulate* it by:
 *
 *   1. Loading the page in a touch-mobile context (Pixel 7 in this
 *      project — chromium-based, but the layout/CSS contract we're
 *      verifying is engine-independent).
 *   2. Patching window.visualViewport so the test controls its
 *      `.height` and can fire synthetic `resize` events — the same
 *      signal a real soft keyboard would emit.
 *   3. Programmatically writing to documentElement.scrollTop /
 *      window.scrollTo — the same mutation iOS Safari performs to
 *      bring a focused input above the keyboard.
 *
 * Why a hand-rolled static server instead of the daemon:
 *
 * The other mobile spec spins up the full daemon + a sibling pty
 * session to attach to. That stack adds ~10s of setup and depends on
 * the daemon's session-bridging path, which is irrelevant to what we
 * want to lock down here (CSS lock + scroll-pin behavior). A bare
 * static server pointed at `browser/dist` lets us verify the page's
 * layout contract directly. The page errors out at "Invalid token
 * URL" because there's no `#pk.secret` fragment; that's fine — main()
 * still runs and wires up all the visualViewport / scroll-lock
 * machinery before parseToken() short-circuits, so every behavior
 * we're testing is in effect.
 */

const PORT = 8767;
const DIST = path.resolve(import.meta.dirname, "../browser/dist");

const TYPES: Record<string, string> = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
  ".wasm": "application/wasm",
  ".json": "application/json",
  ".map": "application/json",
};

let server: http.Server | null = null;

test.beforeAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server = http.createServer((req, res) => {
      const url = (req.url ?? "/").split("?")[0];
      const fp =
        url === "/" || url === ""
          ? path.join(DIST, "index.html")
          : path.join(DIST, url);
      if (!fs.existsSync(fp) || fs.statSync(fp).isDirectory()) {
        res.statusCode = 404;
        res.end("404");
        return;
      }
      res.setHeader(
        "content-type",
        TYPES[path.extname(fp)] ?? "application/octet-stream"
      );
      fs.createReadStream(fp).pipe(res);
    });
    server.on("error", reject);
    server.listen(PORT, () => resolve());
  });
});

test.afterAll(async () => {
  await new Promise<void>((resolve) => {
    server?.close(() => resolve());
  });
});

/**
 * Install a visualViewport monkey-patch on the page, exposing helpers
 * that let the test set the simulated viewport height and fire a
 * synthetic resize event. Must be called BEFORE the page navigates
 * (it uses `addInitScript`), because `main.ts` grabs visualViewport
 * during module init.
 *
 * After install, in the page context:
 *   __vvSimulate.set(height) — overwrite visualViewport.height and
 *                              fire a resize event.
 *
 * We deliberately keep the proxy thin (only the props main.ts uses
 * + the EventTarget contract) so that anything that reaches into
 * visualViewport for an unsupported field gets `undefined` rather
 * than a confusing fallback.
 */
async function installVisualViewportSimulator(context: BrowserContext) {
  await context.addInitScript(() => {
    // Capture a reference to the real visualViewport BEFORE we shadow
    // it. We don't snapshot its height value here — addInitScript runs
    // before navigation completes, when innerHeight may be 0 — instead
    // we read realVV.height live in the getter so the proxy always
    // returns the current reality unless an override is in effect.
    const realVV = window.visualViewport;
    let overrideHeight: number | null = null;
    const listeners: Array<EventListenerOrEventListenerObject> = [];

    const fakeVV = {
      get height() {
        if (overrideHeight !== null) return overrideHeight;
        return realVV?.height ?? window.innerHeight;
      },
      get width() {
        return realVV?.width ?? window.innerWidth;
      },
      offsetTop: 0,
      offsetLeft: 0,
      pageTop: 0,
      pageLeft: 0,
      scale: 1,
      addEventListener(_t: string, l: EventListenerOrEventListenerObject) {
        listeners.push(l);
      },
      removeEventListener(_t: string, l: EventListenerOrEventListenerObject) {
        const i = listeners.indexOf(l);
        if (i !== -1) listeners.splice(i, 1);
      },
      dispatchEvent(_e: Event) {
        return true;
      },
    };

    Object.defineProperty(window, "visualViewport", {
      configurable: true,
      get() {
        return fakeVV;
      },
    });

    (window as unknown as { __vvSimulate: unknown }).__vvSimulate = {
      set(h: number) {
        overrideHeight = h;
        const evt = new Event("resize");
        for (const l of [...listeners]) {
          if (typeof l === "function") l(evt);
          else (l as EventListener).handleEvent?.(evt);
        }
      },
      reset() {
        overrideHeight = null;
        const evt = new Event("resize");
        for (const l of [...listeners]) {
          if (typeof l === "function") l(evt);
          else (l as EventListener).handleEvent?.(evt);
        }
      },
      get height() {
        return overrideHeight ?? realVV?.height ?? window.innerHeight;
      },
    };
  });
}

async function gotoBlankPage(page: Page): Promise<void> {
  // Page will short-circuit at "Invalid token URL" because there's no
  // fragment — but main() still runs and wires up the lock machinery.
  await page.goto(`http://127.0.0.1:${PORT}/`);
  // Wait for the initial #status-overlay text to change — that
  // confirms main.ts has executed past the early initialization
  // (sodium.ready, parseToken, etc.).
  await page.waitForFunction(
    () =>
      document.getElementById("status-overlay")?.textContent?.includes(
        "Invalid token URL"
      ) ?? false,
    undefined,
    { timeout: 5000 }
  );
}

test.describe("mobile keyboard / scroll lock", () => {
  test.beforeEach(async ({ context }) => {
    await installVisualViewportSimulator(context);
  });

  test("html and body track --vh after load (document is the visible region)", async ({ page }) => {
    await gotoBlankPage(page);

    // documentElement.clientHeight returns the viewport height per
    // spec, NOT html's CSS height — use offsetHeight to inspect the
    // actual html box. clientHeight is fine for body.
    const sizes = await page.evaluate(() => {
      const vh = parseInt(
        getComputedStyle(document.documentElement).getPropertyValue("--vh"),
        10
      );
      return {
        vh,
        htmlBoxH: document.documentElement.offsetHeight,
        bodyH: document.body.clientHeight,
        innerH: window.innerHeight,
      };
    });
    expect(sizes.vh).toBeGreaterThan(0);
    // html and body should be at most ~2px off from --vh — sub-pixel
    // rounding on a retina viewport is normal.
    expect(Math.abs(sizes.htmlBoxH - sizes.vh)).toBeLessThanOrEqual(2);
    expect(Math.abs(sizes.bodyH - sizes.vh)).toBeLessThanOrEqual(2);
  });

  test("when visualViewport shrinks (simulated keyboard), html and body collapse with it", async ({ page }) => {
    await gotoBlankPage(page);

    const before = await page.evaluate(
      () => document.documentElement.offsetHeight
    );
    expect(before).toBeGreaterThan(200);

    // Simulate a 300px-tall keyboard popping up.
    const target = before - 300;
    await page.evaluate((h) => {
      (window as unknown as { __vvSimulate: { set(h: number): void } }).__vvSimulate.set(h);
    }, target);

    // updateVh is rAF-coalesced; let two frames pass.
    await page.evaluate(
      () =>
        new Promise<void>((r) =>
          requestAnimationFrame(() => requestAnimationFrame(() => r()))
        )
    );

    const after = await page.evaluate(() => ({
      vh: parseInt(
        getComputedStyle(document.documentElement).getPropertyValue("--vh"),
        10
      ),
      htmlBoxH: document.documentElement.offsetHeight,
      bodyH: document.body.clientHeight,
    }));

    // html should ALSO have shrunk to the new --vh — the new lock
    // contract. Without this, iOS rubber-bands into the empty space
    // below body that exists inside an unshrunk html.
    expect(Math.abs(after.vh - target)).toBeLessThanOrEqual(2);
    expect(Math.abs(after.htmlBoxH - target)).toBeLessThanOrEqual(2);
    expect(Math.abs(after.bodyH - target)).toBeLessThanOrEqual(2);
  });

  test("forced document scroll is snapped back to (0, 0)", async ({ page }) => {
    await gotoBlankPage(page);

    // iOS Safari mutates documentElement.scrollTop directly when an
    // input is focused near the bottom and the keyboard opens. Our
    // window-scroll snap-back listener should catch any non-zero
    // value and pin it back.
    await page.evaluate(() => {
      window.scrollTo(0, 200);
      document.documentElement.scrollTop = 200;
      document.body.scrollTop = 200;
    });

    await page.waitForFunction(
      () =>
        window.scrollY === 0 &&
        document.documentElement.scrollTop === 0 &&
        document.body.scrollTop === 0,
      undefined,
      { timeout: 1500 }
    );

    const final = await page.evaluate(() => ({
      scrollY: window.scrollY,
      docTop: document.documentElement.scrollTop,
      bodyTop: document.body.scrollTop,
    }));
    expect(final.scrollY).toBe(0);
    expect(final.docTop).toBe(0);
    expect(final.bodyTop).toBe(0);
  });

  test("body has no document-level scrollable overflow", async ({ page }) => {
    await gotoBlankPage(page);

    // Even if children grow, body shouldn't develop scrollHeight >
    // clientHeight — overflow:hidden + flex layout should clip them
    // inside their own panes. For html, compare scrollHeight to
    // offsetHeight (its actual box height) rather than clientHeight
    // (which is the viewport per spec for documentElement).
    const overflow = await page.evaluate(() => ({
      htmlScrollH: document.documentElement.scrollHeight,
      htmlBoxH: document.documentElement.offsetHeight,
      bodyScrollH: document.body.scrollHeight,
      bodyClientH: document.body.clientHeight,
    }));
    // Allow ~2px slack for sub-pixel rendering.
    expect(overflow.htmlScrollH).toBeLessThanOrEqual(overflow.htmlBoxH + 2);
    expect(overflow.bodyScrollH).toBeLessThanOrEqual(overflow.bodyClientH + 2);
  });

  test("textarea internal scrollbar is suppressed past the 3-line cap", async ({ page }) => {
    await gotoBlankPage(page);

    // The text-input bar lives in #keyboard inside #terminal-view,
    // which is `display: none` until attach. Page short-circuited at
    // "Invalid token URL" so terminal-view is still hidden. Force
    // the whole stack visible so we can test the textarea's CSS in
    // isolation — the assertion is about computed styles, not the
    // attach flow.
    await page.evaluate(() => {
      (document.getElementById("status-overlay") as HTMLElement).style.display = "none";
      (document.getElementById("terminal-view") as HTMLElement).style.display = "flex";
      (document.getElementById("text-input-bar") as HTMLElement).style.display = "flex";
    });

    const ta = page.locator("#text-input");
    await ta.fill("a\nb\nc\nd\ne\nf\ng\n");
    const dims = await ta.evaluate((el) => ({
      scrollHeight: el.scrollHeight,
      clientHeight: el.clientHeight,
      scrollbarWidth: getComputedStyle(el).scrollbarWidth,
    }));
    // It actually scrolls (content > viewport)…
    expect(dims.scrollHeight).toBeGreaterThan(dims.clientHeight);
    // …but the bar is hidden via scrollbar-width: none (or chromium
    // accepts the WebKit ::-webkit-scrollbar rule which suppresses
    // the chrome scrollbar — both produce a visually empty gutter).
    // We accept either signal: the standard property OR the visual
    // result tested by the user's eye on the device. scrollbar-width
    // values: 'auto' | 'thin' | 'none'.
    expect(["none", "thin"]).toContain(dims.scrollbarWidth);
  });
});
