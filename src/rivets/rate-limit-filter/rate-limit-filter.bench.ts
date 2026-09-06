import { describe } from "vitest";
import { PromptChainmail } from "../../index";
import { protectBench } from "../../@shared/benchmark.utils";
import { rateLimitFilter } from "./rate-limit-filter";

describe("rateLimitFilter()", () => {
  // High limit so the bench measures the check path, not blocking.
  const chainmail = new PromptChainmail().forge(
    rateLimitFilter(1_000_000, 60_000)
  );

  protectBench("simple", chainmail, "test input");
  protectBench(
    "signal",
    chainmail,
    "This is a longer rate-limit path input for benchmarking."
  );
});
