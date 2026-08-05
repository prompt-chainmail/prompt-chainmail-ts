import { describe } from "vitest";
import { PromptChainmail } from "../../index";
import { protectBench } from "../../@shared/benchmark.utils";
import { untrustedWrapper } from "./untrusted-wrapper";

describe("untrustedWrapper()", () => {
  const chainmail = new PromptChainmail().forge(untrustedWrapper());

  protectBench("simple", chainmail, "test input");
  protectBench(
    "signal",
    chainmail,
    "This is a longer untrusted-wrapper path input for benchmarking."
  );
});
