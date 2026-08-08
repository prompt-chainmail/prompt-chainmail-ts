import { defineConfig } from "vitest/config";
import { resolve } from "path";

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "PromptChainmail",
      fileName: (format) =>
        format === "cjs"
          ? "prompt-chainmail.cjs"
          : `prompt-chainmail.${format}.js`,
      formats: ["es", "cjs"],
    },
    rollupOptions: {
      // `node:crypto` is a genuine external dependency, used only as a
      // Node-runtime SHA-256 fallback when Web Crypto (`globalThis.crypto.
      // subtle`) is unavailable (see `classifier-checksum.ts`). Declaring it
      // explicitly external keeps that real, lazy `import("node:crypto")` in
      // the emitted bundle instead of letting Vite's browser-compatibility
      // resolution replace it with an empty stub module (which otherwise
      // shows up as an extra, pointless `__vite-browser-external` chunk).
      external: ["onnxruntime-web", "node:crypto"],
      output: {
        globals: {
          "onnxruntime-web": "ort",
        },
      },
    },
    sourcemap: true,
    minify: "oxc",
    target: ["es2020", "node16"],
  },
  test: {
    globals: true,
    environment: "node",
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      exclude: ["node_modules/", "dist/", "**/*.test.ts", "**/*.config.ts"],
    },
  },
});
