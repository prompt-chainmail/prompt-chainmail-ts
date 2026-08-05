import { describe } from "vitest";
import { PromptChainmail } from "../../index";
import { protectBench } from "../../@shared/benchmark.utils";
import { logger } from "./logger";

describe("logger()", () => {
  const chainmail = new PromptChainmail().forge(logger("log", () => {}));

  protectBench("simple", chainmail, "test input");
  protectBench(
    "signal",
    chainmail,
    "This is a longer logger path input for benchmarking."
  );
});
