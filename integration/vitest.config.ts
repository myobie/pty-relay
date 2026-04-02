import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    testTimeout: 30000,
    hookTimeout: 30000,
    fileParallelism: false,
    include: ["integration/**/*.test.ts"],
    exclude: ["**/*.spec.ts", "node_modules/**"],
    setupFiles: ["./integration/setup.ts"],
  },
});
