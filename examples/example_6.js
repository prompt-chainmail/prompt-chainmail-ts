import { Chainmails } from "../dist/prompt-chainmail.es.js";
import { loadExampleInput, runExampleCases, exitExample } from "./_lib.mjs";

const markdown = loadExampleInput("./example_6.md", import.meta.url);
const body = markdown.replace(/^#[^\n]*\n+/m, "").trim();
const marker = "## Cleaner variant";
const formatted = body.split(marker)[0].trim();
const cleaner = body.includes(marker)
  ? body.slice(body.indexOf(marker) + marker.length).trim()
  : null;

const cases = [
  {
    name: "Formatted indirect tool hijack",
    input: formatted,
    expect: {
      blocked: true,
      flagsInclude: ["tool_use_hijacking"],
    },
  },
];

if (cleaner) {
  cases.push({
    name: "Cleaner indirect tool hijack",
    input: cleaner,
    expect: {
      blocked: true,
      flagsInclude: ["tool_use_hijacking"],
    },
  });
}

const { passed, errors } = await runExampleCases({
  title: "example_6: indirect injection (Chainmails.advanced)",
  description:
    "Document-poisoning / tool-hijack payloads. Formatted and plain-language variants.",
  chainmail: Chainmails.advanced(),
  cases,
});

exitExample(passed, errors);
