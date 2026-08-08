import { PromptChainmail, Rivets } from "../dist/prompt-chainmail.es.js";
import { loadExampleInput, runExampleCases, exitExample } from "./_lib.mjs";

const sections = splitSections(
  loadExampleInput("./example_2.md", import.meta.url)
);

function splitSections(markdown) {
  const body = markdown.replace(/^#[^\n]*\n+/m, "").trim();
  const marker = "## Subtle variant";
  const obvious = body.split(marker)[0].trim();
  const subtle = body.includes(marker)
    ? body.slice(body.indexOf(marker) + marker.length).trim()
    : null;

  const cases = [
    {
      name: "Obvious role confusion",
      input: obvious,
      expect: {
        blocked: true,
        flagsInclude: ["role_confusion"],
        maxConfidence: 0.8,
      },
    },
  ];

  if (subtle) {
    cases.push({
      name: "Subtle jailbreak framing",
      input: subtle,
      expect: {
        // Documents a known gap: subtle role-play jailbreaks are harder to catch.
        blocked: false,
        flagsExclude: ["role_confusion", "instruction_hijacking"],
      },
    });
  }

  return cases;
}

const { passed, errors } = await runExampleCases({
  title: "example_2: roleConfusion (obvious + subtle)",
  description:
    "Classifier-backed role confusion rivet on blunt and subtle jailbreak phrasing.",
  chainmail: new PromptChainmail()
    .forge(Rivets.roleConfusion())
    .forge(Rivets.confidenceFilter(0.8)),
  cases: sections,
});

exitExample(passed, errors);
