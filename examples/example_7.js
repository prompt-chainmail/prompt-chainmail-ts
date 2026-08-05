import { Chainmails } from "../dist/prompt-chainmail.es.js";
import {
  loadExampleInput,
  splitMarkdownSections,
  runExampleCases,
  exitExample,
} from "./_lib.mjs";

const sections = splitMarkdownSections(
  loadExampleInput("./example_7.md", import.meta.url)
);

const expectations = {
  "Hypothetical framing": {
    blocked: false,
    flagsExclude: ["instruction_hijacking", "injection_pattern"],
  },
  "Social engineering": {
    blocked: true,
    flagsInclude: ["role_confusion"],
    maxConfidence: 0.8,
  },
  "Markdown-hidden instruction": {
    blocked: true,
    maxConfidence: 0.8,
  },
  "Indirect email summarization": {
    blocked: true,
    flagsInclude: ["delimiter_confusion"],
    maxConfidence: 0.8,
  },
  "Classic override (control)": {
    blocked: true,
    flagsInclude: ["instruction_hijacking", "injection_pattern"],
    maxConfidence: 0.8,
  },
};

const { passed, errors } = await runExampleCases({
  title: "example_7: real-world attack shapes (Chainmails.strict)",
  description:
    "Mixed production-style prompts. Hypothetical framing still documents a detection gap.",
  chainmail: Chainmails.strict(),
  cases: sections.map(({ name, input }) => ({
    name,
    input,
    expect: expectations[name] ?? { blocked: true },
  })),
});

exitExample(passed, errors);
