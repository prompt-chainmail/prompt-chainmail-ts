import { describe, it, expect, vi } from "vitest";
import { PromptChainmail } from "../../index";
import { logger } from "./logger";
import { ChainmailContext } from "../../types";

describe("logger(...)", () => {
  it("should log processing information with custom function", async () => {
    const logs: ChainmailContext[] = [];
    const mockLogger = (context: ChainmailContext) => logs.push(context);

    const chainmail = new PromptChainmail().forge(logger("log", mockLogger));

    await chainmail.protect("test input");

    expect(logs).toHaveLength(1);
    expect(logs[0].input).toBe("test input");
  });

  it("should use specified log level", async () => {
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const chainmail = new PromptChainmail().forge(logger("warn"));

    await chainmail.protect("test input");

    expect(consoleSpy).toHaveBeenCalledWith(
      "[PromptChainmail]",
      expect.objectContaining({ input_length: 10 })
    );

    consoleSpy.mockRestore();
  });

  it("should default to log level", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});

    const chainmail = new PromptChainmail().forge(logger());

    await chainmail.protect("test");

    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});
