import { bench } from "vitest";

/** Default Tinybench options for regex/string rivets. */
export const BENCH_OPTS = {
  warmupIterations: 10,
  iterations: 50,
  time: 500,
} as const;

/** Longer budget for ONNX classifier rivets. */
export const CLASSIFIER_BENCH_OPTS = {
  warmupIterations: 5,
  iterations: 20,
  time: 2_000,
} as const;

export type Protectable = {
  protect: (input: string) => Promise<unknown>;
};

/**
 * Registers a Vitest bench that measures one `protect()` call.
 */
export function protectBench(
  name: string,
  chainmail: Protectable,
  input: string,
  opts: typeof BENCH_OPTS | typeof CLASSIFIER_BENCH_OPTS = BENCH_OPTS
): void {
  bench(
    name,
    async () => {
      await chainmail.protect(input);
    },
    opts
  );
}
