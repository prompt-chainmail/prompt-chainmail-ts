import { Chainmails } from "../dist/prompt-chainmail.es.js";
import {
  loadExampleInput,
  splitMarkdownSections,
  runExampleCases,
  exitExample,
} from "./_lib.mjs";

const sections = splitMarkdownSections(
  loadExampleInput("./example_0.md", import.meta.url)
);

const { passed, errors } = await runExampleCases({
  title: "example_0: benign baseline (Chainmails.basic)",
  description:
    "Normal user traffic that must stay reachable in production chat flows.",
  chainmail: Chainmails.basic(),
  cases: sections.map(({ name, input }) => ({
    name,
    input,
    expect: {
      blocked: false,
      success: true,
      minConfidence: 0.6,
      flagsExclude: ["sql_injection", "code_injection", "injection_pattern"],
    },
  })),
});

exitExample(passed, errors);
