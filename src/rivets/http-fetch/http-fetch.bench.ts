import { describe, afterAll } from "vitest";
import { PromptChainmail } from "../../index";
import { protectBench } from "../../@shared/benchmark.utils";
import { httpFetch } from "./http-fetch";

describe("httpFetch()", () => {
  const originalFetch = global.fetch;

  // Install mock before forging so every timed iteration hits the same path.
  global.fetch = (async () => ({
    ok: true,
    headers: {
      get: (name: string) => (name === "content-length" ? "100" : null),
    },
    json: async () => ({ safe: true, score: 0.9 }),
  })) as unknown as typeof fetch;

  afterAll(() => {
    global.fetch = originalFetch;
  });

  const chainmail = new PromptChainmail().forge(
    httpFetch("https://api.example.com/validate")
  );

  protectBench("simple", chainmail, "test input");
  protectBench(
    "signal",
    chainmail,
    "This is a longer http-fetch path input for benchmarking."
  );
});
