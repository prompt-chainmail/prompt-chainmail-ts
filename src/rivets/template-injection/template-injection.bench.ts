import { describe } from "vitest";
import { PromptChainmail } from "../../index";
import { protectBench } from "../../@shared/benchmark.utils";
import { templateInjection } from "./template-injection";

describe("templateInjection()", () => {
  const chainmail = new PromptChainmail().forge(templateInjection());

  protectBench("simple", chainmail, "This is a simple test message");
  protectBench(
    "signal",
    chainmail,
    "{{config.secret_key}} ${process.env.SECRET}"
  );
});
