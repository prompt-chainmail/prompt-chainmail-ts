import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { rateLimit } from "./rate-limit";
import { SecurityFlags } from "../rivets.types";

describe("rateLimit(...)", () => {
  it("should enforce rate limiting", async () => {
    const chainmail = new PromptChainmail().forge(rateLimit(2, 60000));

    const result1 = await chainmail.protect("test 1");
    const result2 = await chainmail.protect("test 2");

    expect(result1.success).toBe(true);
    expect(result2.success).toBe(true);

    const result3 = await chainmail.protect("test 3");

    expect(result3.success).toBe(false);
    expect(result3.context.flags).toContain(SecurityFlags.RATE_LIMITED);
    expect(result3.context.blocked).toBe(true);
  });
});
