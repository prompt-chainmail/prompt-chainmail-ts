import { BoundedCache } from "./classifier-cache";
import { CLASSIFIER_LABELS, ClassifierLabel } from "./classifier-labels";
import {
  ClassifierError,
  defaultSessionFactory,
  getClassifierSession,
} from "./classifier-session";
import { windowClassifierRanges } from "./classifier-normalize";
import {
  ClassifierClassification,
  ClassifierManifest,
  ClassifierMatch,
  OrtSessionLike,
  SessionFactory,
} from "./classifier.types";

const DEFAULT_CACHE_SIZE = 256;

function emptyProbabilities(): Record<ClassifierLabel, number> {
  const probabilities = {} as Record<ClassifierLabel, number>;
  for (const label of CLASSIFIER_LABELS) {
    probabilities[label] = 0;
  }
  return probabilities;
}

function buildWindowFeeds(
  window: Uint8Array,
  windowSizeBytes: number,
  factory: SessionFactory
): Record<string, unknown> {
  const ids = new BigInt64Array(windowSizeBytes);
  const mask = new BigInt64Array(windowSizeBytes);

  for (let i = 0; i < window.length; i++) {
    ids[i] = BigInt(window[i]);
    mask[i] = 1n;
  }

  return {
    input_ids: factory.createInt64Tensor(ids, [1, windowSizeBytes]),
    attention_mask: factory.createInt64Tensor(mask, [1, windowSizeBytes]),
  };
}

function readOutputVector(
  output: Record<string, { data: ArrayLike<number | bigint> }>,
  name: string
): number[] {
  const tensor = output[name];
  if (!tensor) {
    throw new ClassifierError(
      "missing_output",
      `Classifier session output is missing the '${name}' tensor`
    );
  }
  return Array.from(tensor.data, (value) => Number(value));
}

/**
 * Runs windowed byte-level classification and aggregates per-label
 * probabilities by taking the maximum across windows, per the artifact
 * contract. One malformed window is isolated and does not discard
 * successful classifications from other windows.
 */
export class ClassifierBackend {
  private readonly cache: BoundedCache<string, ClassifierClassification>;
  private readonly sessionFactory: SessionFactory | undefined;

  constructor(
    options: { cacheSize?: number; sessionFactory?: SessionFactory } = {}
  ) {
    this.cache = new BoundedCache(options.cacheSize ?? DEFAULT_CACHE_SIZE);
    this.sessionFactory = options.sessionFactory;
  }

  async classify(text: string): Promise<ClassifierClassification> {
    const cached = this.cache.get(text);
    if (cached) {
      return cached;
    }

    const { session, manifest } = await getClassifierSession(
      this.sessionFactory
    );

    const classification = await this.runInference(text, session, manifest);
    this.cache.set(text, classification);
    return classification;
  }

  private async runInference(
    text: string,
    session: OrtSessionLike,
    manifest: ClassifierManifest
  ): Promise<ClassifierClassification> {
    let attack_probability = 0;
    const probabilities = emptyProbabilities();
    const matches: ClassifierMatch[] = [];
    let window_errors = 0;

    if (!text.trim()) {
      return { attack_probability, probabilities, matches, window_errors };
    }

    const windows = windowClassifierRanges(
      text,
      manifest.window_size_bytes,
      manifest.window_stride_bytes
    );

    const factory = this.sessionFactory ?? defaultSessionFactory;
    let firstWindowError: unknown = undefined;

    for (let windowIndex = 0; windowIndex < windows.length; windowIndex++) {
      const {
        bytes: window,
        start: windowStart,
        end: windowEnd,
      } = windows[windowIndex];

      try {
        const feeds = buildWindowFeeds(
          window,
          manifest.window_size_bytes,
          factory
        );
        const output = (await session.run(feeds)) as unknown as Record<
          string,
          { data: ArrayLike<number | bigint> }
        >;
        const windowAttackProbability =
          readOutputVector(output, "attack_probability")[0] ?? 0;
        const windowSubtypeProbabilities = readOutputVector(
          output,
          "subtype_probabilities"
        );

        if (windowAttackProbability > attack_probability) {
          attack_probability = windowAttackProbability;
        }

        for (
          let labelIndex = 0;
          labelIndex < CLASSIFIER_LABELS.length;
          labelIndex++
        ) {
          const label = CLASSIFIER_LABELS[labelIndex];
          const probability = windowSubtypeProbabilities[labelIndex] ?? 0;
          if (probability > probabilities[label]) {
            probabilities[label] = probability;
          }
          if (probability >= manifest.thresholds[label]) {
            matches.push({
              label,
              probability,
              window_index: windowIndex,
              window_start_byte: windowStart,
              window_end_byte: windowEnd,
              model_version: manifest.artifact_version,
            });
          }
        }
      } catch (error) {
        // Isolate the failing window; other windows still contribute.
        window_errors += 1;
        if (firstWindowError === undefined) {
          firstWindowError = error;
        }
      }
    }

    if (windows.length > 0 && window_errors === windows.length) {
      throw firstWindowError instanceof ClassifierError
        ? firstWindowError
        : new ClassifierError(
            "window_classification_failed",
            "All classifier windows failed to produce output"
          );
    }

    return { attack_probability, probabilities, matches, window_errors };
  }

  clearCache(): void {
    this.cache.clear();
  }
}
