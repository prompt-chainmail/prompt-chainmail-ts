import { describe } from "vitest";
import { PromptChainmail } from "../../index";
import { protectBench } from "../../@shared/benchmark.utils";
import { structureAnalysis } from "./structure-analysis";

describe("structureAnalysis()", () => {
  const chainmail = new PromptChainmail().forge(structureAnalysis());

  protectBench("simple", chainmail, "This is a simple test message");
  protectBench(
    "signal",
    chainmail,
    "line 1\nline 2\nline 3\nrepeat repeat repeat\n{json: 'data'}"
  );
});
