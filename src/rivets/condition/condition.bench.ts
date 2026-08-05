import { describe } from "vitest";
import { PromptChainmail } from "../../index";
import { protectBench } from "../../@shared/benchmark.utils";
import { condition } from "./condition";

describe("condition()", () => {
  const chainmail = new PromptChainmail().forge(
    condition((ctx) => ctx.sanitized.length > 10)
  );

  protectBench("simple", chainmail, "This is a test message");
  protectBench(
    "signal",
    chainmail,
    "This is a test message with complex conditions"
  );
});
