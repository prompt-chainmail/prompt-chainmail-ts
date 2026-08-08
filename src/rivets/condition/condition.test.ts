import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { condition } from "./condition";
import { ChainmailContext } from "../../types";

describe("condition(...)", () => {
  it("should execute custom conditions", async () => {
    const chainmail = new PromptChainmail().forge(
      condition(
        (ctx: ChainmailContext) => ctx.sanitized.includes("secret"),
        "contains_secret",
        0.5
      )
    );

    const result = await chainmail.protect("This contains a secret word");

    expect(result.context.flags).toContain("contains_secret");
    expect(result.context.confidence).toBe(0.59);
  });
});
