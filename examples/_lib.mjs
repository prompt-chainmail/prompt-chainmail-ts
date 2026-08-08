import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { Rivets } from "../dist/prompt-chainmail.es.js";

export function loadExampleInput(relativeMdPath, importMetaUrl) {
  const path = fileURLToPath(new URL(relativeMdPath, importMetaUrl));
  return readFileSync(path, "utf-8").trim();
}

export function splitMarkdownSections(markdown) {
  const body = markdown.replace(/^#[^\n]*\n+/m, "").trim();
  const firstSection = body.search(/^## /m);

  if (firstSection === -1) {
    return [{ name: "input", input: body }];
  }

  const parts = body.slice(firstSection).split(/^## /m).filter(Boolean);

  return parts.map((block) => {
    const newline = block.indexOf("\n");
    const name = newline === -1 ? block.trim() : block.slice(0, newline).trim();
    const input =
      newline === -1 ? block.trim() : block.slice(newline + 1).trim();
    return { name, input };
  });
}

export function summarizeResult(result) {
  return {
    success: result.success,
    blocked: result.context.blocked,
    confidence: result.context.confidence,
    flags: [...result.context.flags].sort(),
  };
}

export function checkExpectations(result, expect, label = "example") {
  const errors = [];
  const summary = summarizeResult(result);

  if (expect.blocked !== undefined && summary.blocked !== expect.blocked) {
    errors.push(
      `${label}: expected blocked=${expect.blocked}, got ${summary.blocked}`
    );
  }

  if (expect.success !== undefined && summary.success !== expect.success) {
    errors.push(
      `${label}: expected success=${expect.success}, got ${summary.success}`
    );
  }

  if (expect.flagsInclude) {
    for (const flag of expect.flagsInclude) {
      if (!summary.flags.includes(flag)) {
        errors.push(`${label}: expected flag "${flag}" to be present`);
      }
    }
  }

  if (expect.flagsExclude) {
    for (const flag of expect.flagsExclude) {
      if (summary.flags.includes(flag)) {
        errors.push(`${label}: expected flag "${flag}" to be absent`);
      }
    }
  }

  if (
    expect.minConfidence !== undefined &&
    summary.confidence < expect.minConfidence
  ) {
    errors.push(
      `${label}: expected confidence >= ${expect.minConfidence}, got ${summary.confidence}`
    );
  }

  if (
    expect.maxConfidence !== undefined &&
    summary.confidence > expect.maxConfidence
  ) {
    errors.push(
      `${label}: expected confidence <= ${expect.maxConfidence}, got ${summary.confidence}`
    );
  }

  return errors;
}

const CASE_RULE = "=".repeat(80);
const CASE_SUBRULE = "-".repeat(80);

function formatInputPreview(input, maxLen = 160) {
  const singleLine = input.replace(/\s+/g, " ").trim();
  if (singleLine.length <= maxLen) {
    return singleLine;
  }
  return `${singleLine.slice(0, maxLen)}... (${input.length} chars)`;
}

function printCaseHeader(title, input, index, total) {
  const ordinal = total > 1 ? ` (${index + 1}/${total})` : "";
  console.log(CASE_RULE);
  console.log(`case: ${title}${ordinal}`);
  console.log(CASE_SUBRULE);
  console.log(`input (${input.length} chars): ${formatInputPreview(input)}`);
  console.log("output:");
}

export async function runExample({
  title,
  chainmail,
  input,
  expect,
  caseIndex = 0,
  caseTotal = 1,
  printHeader = true,
}) {
  if (printHeader) {
    printCaseHeader(title, input, caseIndex, caseTotal);
  }

  const result = await chainmail.clone().forge(Rivets.logger()).protect(input);
  const errors = expect ? checkExpectations(result, expect, title) : [];

  return {
    result,
    summary: summarizeResult(result),
    errors,
    passed: errors.length === 0,
  };
}

export async function runExampleCases({ title, chainmail, cases }) {
  const allErrors = [];
  const caseTotal = cases.length;

  if (title) {
    console.log(title);
  }

  for (const [index, testCase] of cases.entries()) {
    const caseTitle = testCase.name ?? `case_${index + 1}`;
    const { errors } = await runExample({
      title: caseTitle,
      chainmail,
      input: testCase.input,
      expect: testCase.expect,
      caseIndex: index,
      caseTotal,
    });
    allErrors.push(...errors);
  }

  return { passed: allErrors.length === 0, errors: allErrors };
}

export function exitExample(passed, errors) {
  if (!passed) {
    for (const error of errors) {
      console.error(error);
    }
    process.exit(1);
  }
}
