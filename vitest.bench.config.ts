import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.bench.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    fileParallelism: false,
    sequence: {
      concurrent: false,
    },
  },
});
