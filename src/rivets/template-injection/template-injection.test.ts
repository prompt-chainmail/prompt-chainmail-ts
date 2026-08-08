import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { templateInjection } from "./template-injection";
import { SecurityFlags } from "../rivets.types";

describe("templateInjection()", () => {
  it("should detect template injection", async () => {
    const chainmail = new PromptChainmail().forge(templateInjection());

    const result = await chainmail.protect("{{config.secret_key}}");

    expect(result.context.flags).toContain(SecurityFlags.TEMPLATE_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect Jinja2 template injection", async () => {
    const chainmail = new PromptChainmail().forge(templateInjection());

    const result = await chainmail.protect(
      "{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}"
    );

    expect(result.context.flags).toContain(SecurityFlags.TEMPLATE_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect ERB template injection", async () => {
    const chainmail = new PromptChainmail().forge(templateInjection());

    const result = await chainmail.protect("<%= system('whoami') %>");

    expect(result.context.flags).toContain(SecurityFlags.TEMPLATE_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect Twig template injection", async () => {
    const chainmail = new PromptChainmail().forge(templateInjection());

    const result = await chainmail.protect(
      "{{_self.env.registerUndefinedFilterCallback('exec')}}"
    );

    expect(result.context.flags).toContain(SecurityFlags.TEMPLATE_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });

  it("should detect Smarty template injection", async () => {
    const chainmail = new PromptChainmail().forge(templateInjection());

    const result = await chainmail.protect("{php}echo `id`;{/php}");

    expect(result.context.flags).toContain(SecurityFlags.TEMPLATE_INJECTION);
    expect(result.context.confidence).toBeLessThan(1.0);
  });
});
