import { describe } from "vitest";
import { PromptChainmail } from "../../index";
import { protectBench } from "../../@shared/benchmark.utils";
import { codeInjection } from "./code-injection";

describe("codeInjection()", () => {
  const chainmail = new PromptChainmail().forge(codeInjection());

  protectBench("simple", chainmail, "This is a simple test message");
  protectBench(
    "signal",
    chainmail,
    "eval('malicious code'); console.log('injected');"
  );
});
