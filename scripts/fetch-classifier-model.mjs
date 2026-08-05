#!/usr/bin/env node
/**
 * Fetches a pinned model_version from prompt-chainmail-models and adapts it
 * for the TypeScript runtime:
 *   - src/@shared/classifier/manifest.json
 *   - src/@shared/classifier/normalization-vectors.json
 *   - src/@shared/classifier/classifier-model-data.generated.ts (base64 embed)
 *
 * Source resolution order:
 *   1. MODELS_REPO env / --models-repo (local checkout)
 *   2. Sibling ../prompt-chainmail-models
 *   3. GitHub raw URLs for prompt-chainmail/prompt-chainmail-models
 */
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  readdirSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const pinPath = resolve(repoRoot, "classifier-model-version.json");
const classifierDir = resolve(repoRoot, "src/@shared/classifier");
const generatedModulePath = resolve(
  classifierDir,
  "classifier-model-data.generated.ts"
);

const MODEL_FILENAME_BY_FORMAT = {
  INT8: "classifier.int8.onnx",
  FLOAT32: "classifier.onnx",
};

const GITHUB_OWNER_REPO = "prompt-chainmail/prompt-chainmail-models";
const GITHUB_BRANCH = "main";

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseArgs(argv) {
  const args = { modelsRepo: process.env.MODELS_REPO || null, version: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--models-repo") {
      args.modelsRepo = argv[++i];
    } else if (arg === "--model-version") {
      args.version = argv[++i];
    } else if (arg === "--help" || arg === "-h") {
      args.help = true;
    }
  }
  return args;
}

function loadPin() {
  return JSON.parse(readFileSync(pinPath, "utf-8"));
}

function localVersionDir(modelsRepo, version) {
  return resolve(modelsRepo, "models", version);
}

async function readLocalOrRemote(
  versionDir,
  filename,
  version,
  vendoredFallbackPath
) {
  const localPath = resolve(versionDir, filename);
  if (existsSync(localPath)) {
    return { bytes: readFileSync(localPath), source: `local:${localPath}` };
  }

  const url = `https://raw.githubusercontent.com/${GITHUB_OWNER_REPO}/${GITHUB_BRANCH}/models/${encodeURIComponent(version)}/${encodeURIComponent(filename)}`;
  let fetchStatus = "unknown error";
  try {
    const response = await fetch(url);
    if (response.ok) {
      return {
        bytes: Buffer.from(await response.arrayBuffer()),
        source: `github:${url}`,
      };
    }
    fetchStatus = `HTTP ${response.status}`;
  } catch (error) {
    fetchStatus = error instanceof Error ? error.message : String(error);
  }

  if (vendoredFallbackPath && existsSync(vendoredFallbackPath)) {
    console.warn(
      `Could not fetch ${filename} (${fetchStatus}); using already-vendored ${vendoredFallbackPath}`
    );
    return {
      bytes: readFileSync(vendoredFallbackPath),
      source: `vendored:${vendoredFallbackPath}`,
    };
  }

  throw new Error(
    `Failed to fetch ${filename} for model_version=${version}: ${fetchStatus} (${url}). ` +
      `Clone prompt-chainmail-models as a sibling, pass --models-repo, or vendor files under src/@shared/classifier/.`
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(`Usage: node scripts/fetch-classifier-model.mjs [--model-version V] [--models-repo PATH]

Reads classifier-model-version.json (unless --model-version is set) and
vendors the model into src/@shared/classifier/.`);
    return;
  }

  const pin = loadPin();
  const version = args.version || pin.model_version;
  if (!version) {
    throw new Error(
      "No model_version in classifier-model-version.json or --model-version"
    );
  }

  const siblingDefault = resolve(repoRoot, "../prompt-chainmail-models");
  const modelsRepo = resolve(args.modelsRepo || siblingDefault);
  const versionDir = localVersionDir(modelsRepo, version);
  const usingLocal = existsSync(versionDir);

  if (usingLocal) {
    console.log(`Using local models repo: ${versionDir}`);
  } else {
    console.log(
      `Local models folder missing (${versionDir}); will try GitHub raw for ${GITHUB_OWNER_REPO}@${GITHUB_BRANCH}`
    );
  }

  const vendoredManifest = resolve(classifierDir, "manifest.json");
  const vendoredVectors = resolve(classifierDir, "normalization-vectors.json");

  const { bytes: manifestBytes } = await readLocalOrRemote(
    versionDir,
    "manifest.json",
    version,
    vendoredManifest
  );
  const manifest = JSON.parse(manifestBytes.toString("utf-8"));

  const quantizationFormat = manifest.quantization?.format;
  const modelFilename = MODEL_FILENAME_BY_FORMAT[quantizationFormat];
  if (!modelFilename) {
    throw new Error(
      `Unknown manifest quantization.format: ${quantizationFormat}. Expected one of ${Object.keys(MODEL_FILENAME_BY_FORMAT).join(", ")}.`
    );
  }

  if (typeof manifest.attack_threshold !== "number") {
    throw new Error(
      "Manifest is missing attack_threshold. Expected dual-head export contract."
    );
  }

  // ONNX itself is only stored as base64 in the generated module; when the
  // models repo is unreachable, rebuild the generated module from that embed
  // only if the checksum still matches the (vendored) manifest.
  const { bytes: modelBytes } = await readLocalOrRemote(
    versionDir,
    modelFilename,
    version,
    null
  ).catch(async (error) => {
    if (!existsSync(generatedModulePath)) {
      throw error;
    }
    const generated = readFileSync(generatedModulePath, "utf-8");
    const match = generated.match(
      /export const CLASSIFIER_MODEL_BASE64 = "([^"]+)";/
    );
    if (!match) {
      throw error;
    }
    const bytes = Buffer.from(match[1], "base64");
    console.warn(
      `Could not fetch ${modelFilename}; reusing base64 from ${generatedModulePath}`
    );
    return { bytes, source: `vendored:${generatedModulePath}` };
  });
  const computedChecksum = sha256Hex(modelBytes);
  if (computedChecksum !== manifest.model_sha256) {
    throw new Error(
      `Model checksum mismatch: manifest says ${manifest.model_sha256}, computed ${computedChecksum}.`
    );
  }

  const { bytes: vectorsBytes } = await readLocalOrRemote(
    versionDir,
    "normalization-vectors.json",
    version,
    vendoredVectors
  );

  mkdirSync(classifierDir, { recursive: true });
  writeFileSync(resolve(classifierDir, "manifest.json"), manifestBytes);
  writeFileSync(
    resolve(classifierDir, "normalization-vectors.json"),
    vectorsBytes
  );

  const base64 = modelBytes.toString("base64");
  const generated = `/**
 * GENERATED FILE. Run \`npm run fetch:classifier\` to regenerate.
 * Source: prompt-chainmail-models models/${version}/${modelFilename}
 * model_version: ${version}
 * quantization.format: ${quantizationFormat}
 * Two-output contract: attack_probability [B,1] + subtype_probabilities [B,10].
 * Do not hand-edit.
 */

export const CLASSIFIER_MODEL_BASE64 = "${base64}";

export const CLASSIFIER_MODEL_SHA256 = "${computedChecksum}";

export const CLASSIFIER_MODEL_BYTE_LENGTH = ${modelBytes.length};
`;

  writeFileSync(generatedModulePath, generated);

  // Keep pin file aligned if a CLI override was used
  if (args.version && args.version !== pin.model_version) {
    writeFileSync(
      pinPath,
      JSON.stringify(
        {
          ...pin,
          model_version: args.version,
        },
        null,
        2
      ) + "\n"
    );
  }

  console.log("Fetched classifier model for TypeScript runtime:");
  console.log(`  model_version: ${version}`);
  console.log(`  filename: ${modelFilename}`);
  console.log(`  quantization.format: ${quantizationFormat}`);
  console.log(`  model bytes: ${modelBytes.length}`);
  console.log(`  sha256: ${computedChecksum}`);
  console.log(`  attack_threshold: ${manifest.attack_threshold}`);
  if (usingLocal) {
    console.log(
      `  files in version dir: ${readdirSync(versionDir).join(", ")}`
    );
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
