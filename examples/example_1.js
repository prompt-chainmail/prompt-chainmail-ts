import { PromptChainmail, Rivets } from "../dist/prompt-chainmail.es.js";
import { loadExampleInput, runExample, exitExample } from "./_lib.mjs";

const input = loadExampleInput("./example_1.md", import.meta.url);

const { passed, errors } = await runExample({
  title: "example_1: sqlInjection (security review context)",
  description:
    "User pastes dangerous SQL from a ticket while asking for remediation guidance.",
  chainmail: new PromptChainmail()
    .forge(Rivets.sqlInjection())
    .forge(Rivets.confidenceFilter(0.8)),
  input,
  expect: {
    blocked: true,
    flagsInclude: ["sql_injection"],
    maxConfidence: 0.8,
  },
});

exitExample(passed, errors);
