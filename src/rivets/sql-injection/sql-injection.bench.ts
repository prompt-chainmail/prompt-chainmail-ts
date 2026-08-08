import { describe } from "vitest";
import { PromptChainmail } from "../../index";
import { protectBench } from "../../@shared/benchmark.utils";
import { sqlInjection } from "./sql-injection";

describe("sqlInjection()", () => {
  const chainmail = new PromptChainmail().forge(sqlInjection());

  protectBench("simple", chainmail, "This is a simple test message");
  protectBench("signal", chainmail, "1' UNION SELECT password FROM users--");
});
