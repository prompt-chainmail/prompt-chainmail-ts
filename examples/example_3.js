import { PromptChainmail, Rivets } from "../dist/prompt-chainmail.es.js";
import { loadExampleInput, runExample, exitExample } from "./_lib.mjs";

const input = loadExampleInput("./example_3.md", import.meta.url);

const { passed, errors } = await runExample({
  title: "example_3: codeInjection (pentest review context)",
  description:
    "Security review text that quotes dangerous execution patterns from a report.",
  chainmail: new PromptChainmail()
    .forge(Rivets.codeInjection())
    .forge(Rivets.confidenceFilter(0.8)),
  input,
  expect: {
    blocked: true,
    flagsInclude: ["code_injection"],
    maxConfidence: 0.8,
  },
});

exitExample(passed, errors);
