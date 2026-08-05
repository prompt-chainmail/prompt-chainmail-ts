import { describe } from "vitest";
import { PromptChainmail } from "../../index";
import { protectBench } from "../../@shared/benchmark.utils";
import { sanitize } from "./sanitize";

describe("sanitize()", () => {
  const chainmail = new PromptChainmail().forge(sanitize());

  protectBench("simple", chainmail, "This is a simple test message");
  protectBench(
    "signal",
    chainmail,
    "<script>alert('xss')</script><div>Content</div>"
  );
});
