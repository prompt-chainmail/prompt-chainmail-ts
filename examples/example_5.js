import { PromptChainmail, Rivets } from "../dist/prompt-chainmail.es.js";
import { loadExampleInput, runExampleCases, exitExample } from "./_lib.mjs";

const markdown = loadExampleInput("./example_5.md", import.meta.url);
const body = markdown.replace(/^#[^\n]*\n+/m, "").trim();
const marker = "## Translation obfuscation";
const englishBlock = body.split(marker)[0].trim();
const translationBlock = body.includes(marker)
  ? body.slice(body.indexOf(marker) + marker.length).trim()
  : null;

const cases = [
  {
    name: "Direct instruction hijacking",
    input: englishBlock,
    expect: {
      blocked: true,
      flagsInclude: ["instruction_hijacking"],
      maxConfidence: 0.8,
    },
  },
];

if (translationBlock) {
  cases.push({
    name: "Spanish translation obfuscation",
    input: translationBlock,
    expect: {
      // Known gap unless multilingual classifier recall improves.
      blocked: false,
    },
  });
}

const { passed, errors } = await runExampleCases({
  title: "example_5: instructionHijacking (direct + translated)",
  description:
    "Classifier-backed instruction hijacking on English overrides and translated variants.",
  chainmail: new PromptChainmail()
    .forge(Rivets.instructionHijacking())
    .forge(Rivets.confidenceFilter(0.8)),
  cases,
});

exitExample(passed, errors);
