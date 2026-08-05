import { ClassifierLabel } from "./classifier-labels";

/**
 * @description
 * Versioned artifact manifest contract. Field names intentionally match
 * `prompt-chainmail-models` `manifest.schema.json` (snake_case) so the manifest
 * JSON can be validated and consumed without a translation layer, and so
 * Rust/Java implementations reading the same manifest see identical field
 * names.
 */
export interface ClassifierManifest {
  /**
   * Decision threshold for the binary attack head (`attack_probability`).
   */
  attack_threshold: number;
  /**
   * Subtype thresholds only gate flags once a row also clears this gate.
   */
  thresholds: Record<ClassifierLabel, number>;

  schema_version: 1;
  artifact_version: string;
  model_sha256: string;
  model_size_bytes: number;
  labels: ClassifierLabel[];
  normalization_version: string;
  window_size_bytes: number;
  window_stride_bytes: number;
  corpus_revision: string;
  quantization: {
    format: "INT8" | "FLOAT32";
    method: string;
  };
  metrics: {
    macro_f1: number;
    macro_recall: number;
    benign_false_positive_rate: number;
    attack_precision: number;
    attack_recall: number;
    attack_f1: number;
    per_language: Record<string, { recall: number }>;
  };
  release_quality: boolean;
  gate_failures: string[];
}

/** A single classifier match, evidence for one label crossing its threshold. */
export interface ClassifierMatch {
  label: ClassifierLabel;
  probability: number;
  window_index: number;
  window_start_byte: number;
  window_end_byte: number;
  model_version: string;
}

/**
 * Semantic detection result, independent of the removed vector-search
 * module. Field names match the prior vector-search result shape so rivet
 * metadata keys remain stable.
 */
export interface SemanticDetectionResult {
  is_attack: boolean;
  attack_types: string[];
  confidence: number;
  risk_score: number;
  detected_language: string;
  details: string[];
  matches?: ClassifierMatch[];
  detector_error?: string;
}

/**
 * @description
 * Full classification for one input string from the dual-head model: an
 * overall binary attack probability plus per-label subtype probabilities.
 * Both are aggregated by taking the maximum across windows, independently
 * of one another.
 */
export interface ClassifierClassification {
  /** Max, across windows, of the binary attack head's sigmoid output. */
  attack_probability: number;
  /** Max, across windows, of the per-label subtype head's sigmoid output. */
  probabilities: Record<ClassifierLabel, number>;
  /** Subtype-label matches whose probability crossed its manifest threshold. */
  matches: ClassifierMatch[];
  /** Present when a window failed to classify; other windows still contribute. */
  window_errors: number;
}

/**
 * Backend abstraction consumed by rivets. Implementations must never include
 * prompt text in thrown errors or logs.
 */
export interface DetectionBackend {
  detect(text: string, languageCode: string): Promise<SemanticDetectionResult>;
}

export interface RiskCalculationConfig {
  cybercrime_index_base: number;
  max_attack_type_multiplier: number;
  attack_type_divisor: number;
  high_risk_boost: number;
  max_risk_score: number;
  fallback_threshold?: number;
}

export interface ClassifierDetectionConfig {
  risk_calculation: RiskCalculationConfig;
}

/** Minimal onnxruntime-web tensor/session surface, kept narrow for testability. */
export interface OrtTensorLike {
  data: ArrayLike<number | bigint>;
  dims: readonly number[];
  type: string;
}

export interface OrtSessionLike {
  run(feeds: Record<string, unknown>): Promise<Record<string, OrtTensorLike>>;
}

export interface SessionFactory {
  createSession(modelBytes: Uint8Array): Promise<OrtSessionLike>;
  createInt64Tensor(data: BigInt64Array, dims: readonly number[]): unknown;
}
