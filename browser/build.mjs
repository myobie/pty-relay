// Build script for the pty-relay web UI.
//
// Bundles browser/src/main.ts into browser/dist/main.js using esbuild
// and copies browser/src/index.html + browser/vendor/* into browser/dist
// so the self-hosted relay can serve the whole thing as a static tree.
//
// Why external instead of bundled:
//
// @xterm/xterm, @xterm/addon-fit, libsodium-wrappers-sumo, and
// libsodium-sumo are already vendored as ESM under browser/vendor/ and
// loaded via an importmap in the HTML. We keep them external so the
// bundle only contains our own code — the bundled main.js stays small
// (~15 KB) and we don't need npm packages for xterm (which isn't
// published under that name). The importmap in the HTML resolves the
// bare specifiers at runtime.

import * as esbuild from "esbuild";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const srcDir = path.join(here, "src");
const distDir = path.join(here, "dist");
const vendorDir = path.join(here, "vendor");

// Bare-specifier imports that stay external — resolved at runtime by the
// importmap in index.html.
const EXTERNAL = [
  "@xterm/xterm",
  "@xterm/addon-fit",
  "libsodium-wrappers-sumo",
  "libsodium-sumo",
];

function rimraf(p) {
  if (fs.existsSync(p)) fs.rmSync(p, { recursive: true, force: true });
}

function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const sp = path.join(src, entry.name);
    const dp = path.join(dest, entry.name);
    if (entry.isDirectory()) copyDir(sp, dp);
    else fs.copyFileSync(sp, dp);
  }
}

async function build() {
  rimraf(distDir);
  fs.mkdirSync(distDir, { recursive: true });

  await esbuild.build({
    entryPoints: [path.join(srcDir, "main.ts")],
    outfile: path.join(distDir, "main.js"),
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "browser",
    sourcemap: false,
    minify: false,
    external: EXTERNAL,
    logLevel: "info",
  });

  // Copy HTML shell
  fs.copyFileSync(path.join(srcDir, "index.html"), path.join(distDir, "index.html"));

  // Copy vendor tree so the dist directory is self-contained and the
  // relay can serve /vendor/* out of the same parent as index.html.
  copyDir(vendorDir, path.join(distDir, "vendor"));

  console.log("built browser UI -> " + path.relative(process.cwd(), distDir));
}

build().catch((err) => {
  console.error(err);
  process.exit(1);
});
