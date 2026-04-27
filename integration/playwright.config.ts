import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  // Default match — desktop project picks these up.
  testMatch: "**/*.spec.ts",
  timeout: 60000,
  retries: 0,
  workers: 1,
  use: {
    headless: true,
  },
  projects: [
    {
      name: "desktop",
      use: { ...devices["Desktop Chrome"] },
      testMatch: "web.spec.ts",
    },
    {
      // Mobile project — runs only the mobile-specific spec, with a
      // realistic touch-enabled viewport. The custom keyboard bar
      // (quick-bar / key-panel / text-input) only renders meaningfully
      // here; testing it on desktop would just exercise mouse clicks
      // against buttons, which doesn't validate the touch flow we
      // actually ship.
      //
      // We use Pixel 7 (chromium-based mobile emulation) instead of
      // iPhone (webkit) to avoid forcing every contributor to
      // `playwright install webkit` — the failure modes we're testing
      // here are DOM/JS, not Safari quirks, so chromium with
      // hasTouch + mobile viewport is sufficient.
      name: "mobile",
      use: { ...devices["Pixel 7"] },
      testMatch: "web-mobile.spec.ts",
    },
  ],
});
