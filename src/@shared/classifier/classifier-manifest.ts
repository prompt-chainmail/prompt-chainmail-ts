import manifestJson from "./manifest.json" with { type: "json" };
import { CLASSIFIER_LABELS } from "./classifier-labels";
import { ClassifierManifest } from "./classifier.types";

export class ClassifierManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClassifierManifestError";
  }
}

const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/;

function isProbability(value: unknown): value is number {
  return typeof value === "number" && value >= 0 && value <= 1;
}

function fail(message: string): never {
  throw new ClassifierManifestError(message);
}

/**
 * Structural validation for the classifier manifest contract. Deliberately
 * hand-rolled (no JSON-schema dependency) to keep the runtime dependency
 * surface minimal; `manifest.schema.json` remains the authoritative,
 * language-agnostic contract for Rust/Java implementations.
 */
export function validateManifest(candidate: unknown): ClassifierManifest {
  if (typeof candidate !== "object" || candidate === null) {
    fail("Classifier manifest must be an object");
  }

  const manifest = candidate as Record<string, unknown>;

  if (manifest.schema_version !== 1) {
    fail(
      `Unsupported classifier manifest schema_version: ${manifest.schema_version}`
    );
  }

  if (
    typeof manifest.artifact_version !== "string" ||
    manifest.artifact_version.length === 0
  ) {
    fail("Classifier manifest artifact_version must be a non-empty string");
  }

  if (
    typeof manifest.model_sha256 !== "string" ||
    !SHA256_HEX_PATTERN.test(manifest.model_sha256)
  ) {
    fail("Classifier manifest model_sha256 must be a 64-character hex string");
  }

  if (
    typeof manifest.model_size_bytes !== "number" ||
    manifest.model_size_bytes <= 0 ||
    manifest.model_size_bytes > 10 * 1024 * 1024
  ) {
    fail(
      "Classifier manifest model_size_bytes must be between 1 byte and 10 MiB"
    );
  }

  if (
    !Array.isArray(manifest.labels) ||
    manifest.labels.length !== CLASSIFIER_LABELS.length ||
    !manifest.labels.every((label, index) => label === CLASSIFIER_LABELS[index])
  ) {
    fail(
      `Classifier manifest labels must exactly equal ${JSON.stringify(CLASSIFIER_LABELS)} in order`
    );
  }

  if (manifest.normalization_version !== "nfkc-whitespace-lower-v1") {
    fail(
      `Unsupported classifier normalization_version: ${manifest.normalization_version}`
    );
  }

  if (
    typeof manifest.window_size_bytes !== "number" ||
    manifest.window_size_bytes <= 0
  ) {
    fail("Classifier manifest window_size_bytes must be a positive number");
  }

  if (
    typeof manifest.window_stride_bytes !== "number" ||
    manifest.window_stride_bytes <= 0
  ) {
    fail("Classifier manifest window_stride_bytes must be a positive number");
  }

  const thresholds = manifest.thresholds as Record<string, unknown> | undefined;
  if (typeof thresholds !== "object" || thresholds === null) {
    fail("Classifier manifest thresholds must be an object");
  }
  for (const label of CLASSIFIER_LABELS) {
    if (!isProbability(thresholds[label])) {
      fail(
        `Classifier manifest thresholds.${label} must be a number between 0 and 1`
      );
    }
  }

  if (!isProbability(manifest.attack_threshold)) {
    fail(
      "Classifier manifest attack_threshold must be a number between 0 and 1"
    );
  }

  if (
    typeof manifest.corpus_revision !== "string" ||
    manifest.corpus_revision.length === 0
  ) {
    fail("Classifier manifest corpus_revision must be a non-empty string");
  }

  const quantization = manifest.quantization as
    | Record<string, unknown>
    | undefined;
  if (
    typeof quantization !== "object" ||
    quantization === null ||
    (quantization.format !== "INT8" && quantization.format !== "FLOAT32") ||
    typeof quantization.method !== "string" ||
    quantization.method.length === 0
  ) {
    fail(
      "Classifier manifest quantization must be { format: 'INT8' | 'FLOAT32', method: string }"
    );
  }

  const metrics = manifest.metrics as Record<string, unknown> | undefined;
  if (
    typeof metrics !== "object" ||
    metrics === null ||
    !isProbability(metrics.macro_f1) ||
    !isProbability(metrics.macro_recall) ||
    !isProbability(metrics.benign_false_positive_rate) ||
    !isProbability(metrics.attack_precision) ||
    !isProbability(metrics.attack_recall) ||
    !isProbability(metrics.attack_f1) ||
    typeof metrics.per_language !== "object" ||
    metrics.per_language === null
  ) {
    fail("Classifier manifest metrics are missing or malformed");
  }

  if (typeof manifest.release_quality !== "boolean") {
    fail("Classifier manifest release_quality must be a boolean");
  }

  if (!Array.isArray(manifest.gate_failures)) {
    fail("Classifier manifest gate_failures must be an array of strings");
  }

  if (
    manifest.release_quality === false &&
    manifest.gate_failures.length === 0
  ) {
    fail(
      "Classifier manifest release_quality is false but gate_failures is empty; " +
        "a non-release artifact must record why it failed release gates"
    );
  }

  return manifest as unknown as ClassifierManifest;
}

export const CLASSIFIER_MANIFEST: ClassifierManifest =
  validateManifest(manifestJson);
