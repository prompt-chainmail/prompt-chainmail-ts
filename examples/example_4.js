import { PromptChainmail, Rivets } from "../dist/prompt-chainmail.es.js";
import { loadExampleInput, runExample, exitExample } from "./_lib.mjs";

const input = loadExampleInput("./example_4.md", import.meta.url);

const { passed, errors } = await runExample({
  title: "example_4: encodingDetection (obfuscation lab)",
  description: "Mixed encodings that decode to instruction-override language.",
  chainmail: new PromptChainmail()
    .forge(Rivets.encodingDetection())
    .forge(Rivets.confidenceFilter(0.8)),
  input,
  expect: {
    blocked: true,
    flagsInclude: ["base64_encoding", "rot13_encoding"],
    maxConfidence: 0.8,
  },
});

exitExample(passed, errors);
