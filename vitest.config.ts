import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    exclude: ["integration/**", "node_modules/**"],
    setupFiles: ["./test/setup.ts"],
  },
});
