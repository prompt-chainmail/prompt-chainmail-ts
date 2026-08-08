import { PromptChainmail, Rivets } from "../dist/prompt-chainmail.es.js";
import {
  loadExampleInput,
  splitMarkdownSections,
  runExampleCases,
  exitExample,
} from "./_lib.mjs";

const sections = splitMarkdownSections(
  loadExampleInput("./example_8.md", import.meta.url)
);

const { passed, errors } = await runExampleCases({
  title: "example_8: toolUseHijacking (classifier-backed)",
  description: "Indirect tool-use hijacking vs benign agent tool usage.",
  chainmail: new PromptChainmail()
    .forge(Rivets.toolUseHijacking())
    .forge(Rivets.confidenceFilter(0.8)),
  cases: sections.map(({ name, input }) => ({
    name,
    input,
    expect:
      name === "Benign agent usage"
        ? {
            blocked: false,
            flagsExclude: ["tool_use_hijacking"],
          }
        : {
            blocked: true,
            flagsInclude: ["tool_use_hijacking"],
            maxConfidence: 0.8,
          },
  })),
});

exitExample(passed, errors);
