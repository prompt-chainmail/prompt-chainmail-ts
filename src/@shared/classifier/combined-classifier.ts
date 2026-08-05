import { ClassifierBackend } from "./classifier-backend";
import { ClassifierConfigLoader } from "./classifier-config";
import { ClassifierFamily, labelsForFamily } from "./classifier-labels";
import { CLASSIFIER_MANIFEST } from "./classifier-manifest";
import {
  calculateLanguageCodeRiskScore,
  languageGroupForCode,
} from "./classifier-risk";
import { ClassifierError } from "./classifier-session";
import { SemanticDetectionResult } from "./classifier.types";

export interface ClassifyFamilyOptions {
  /** Optional additional confidence floor on top of per-label manifest thresholds. */
  confidenceThreshold?: number;
}

function emptyResult(languageCode: string): SemanticDetectionResult {
  return {
    is_attack: false,
    attack_types: [],
    confidence: 0,
    risk_score: 0,
    detected_language: languageCode,
    details: [],
    matches: [],
  };
}

/**
 * Singleton-friendly wrapper around the classifier backend. Both
 * `instructionHijacking()`, `roleConfusion()`, and `toolUseHijacking()` share one instance so the
 * same sanitized text is classified once and filtered per attack family.
 */
export class CombinedClassifier {
  constructor(
    private readonly backend: ClassifierBackend = new ClassifierBackend()
  ) {}

  async classifyFamily(
    text: string,
    languageCode: string,
    family: ClassifierFamily,
    options: ClassifyFamilyOptions = {}
  ): Promise<SemanticDetectionResult> {
    if (!text?.trim()) {
      return emptyResult(languageCode);
    }

    let classification;
    try {
      classification = await this.backend.classify(text);
    } catch (error) {
      const detectorErrorCode =
        error instanceof ClassifierError ? error.code : "unknown_error";
      return {
        ...emptyResult(languageCode),
        details: [`Classifier detection error: ${detectorErrorCode}`],
        detector_error: detectorErrorCode,
      };
    }

    const familyLabels = labelsForFamily(family);
    const languageGroup = languageGroupForCode(languageCode);
    const { risk_calculation } = ClassifierConfigLoader.get(family);

    const matches = classification.matches.filter((match) =>
      familyLabels.includes(match.label)
    );
    const attackTypes = Array.from(
      new Set(matches.map((match) => match.label))
    );

    // `confidence` reports the shared attack-head probability (not a
    // family-specific subtype max) so instruction_hijacking_confidence and
    // role_confusion_confidence describe the same underlying signal
    // consistently. Gating still requires a family-relevant subtype above
    // its own threshold, so a high attack probability from one family's
    // pattern cannot flip the other family's flags (cross-family isolation).
    const confidence = classification.attack_probability;
    const passesAttackThreshold =
      confidence >= CLASSIFIER_MANIFEST.attack_threshold;
    const passesConfidenceFloor =
      options.confidenceThreshold === undefined ||
      confidence >= options.confidenceThreshold;
    // Indirect tool-use hijacks often score high on the subtype head while the
    // shared attack head stays below the global gate. Confirm on subtype alone
    // for that family; instruction/role families keep dual-head gating.
    const passesAttackGate =
      passesAttackThreshold || family === "tool_use_hijacking";
    const isAttack =
      passesAttackGate && attackTypes.length > 0 && passesConfidenceFloor;

    // Risk is only meaningful for a confirmed attack: a high shared
    // attack_probability with no relevant family subtype (or a subtype match
    // below the shared attack gate) must not leak a non-zero risk_score, or
    // cross-family isolation would be defeated by the risk field even though
    // `attack_types`/`is_attack` stay correctly empty/false.
    const riskScore = isAttack
      ? calculateLanguageCodeRiskScore(
          confidence,
          languageGroup,
          attackTypes.length,
          risk_calculation
        )
      : 0;

    const details = matches.map(
      (match) =>
        `Classifier label ${match.label} probability ${match.probability.toFixed(3)} (window ${match.window_index})`
    );

    return {
      is_attack: isAttack,
      attack_types: isAttack ? attackTypes : [],
      confidence,
      risk_score: riskScore,
      detected_language: languageGroup || languageCode,
      details,
      matches,
    };
  }
}

let sharedClassifier: CombinedClassifier | null = null;

/** Shared classifier instance reused across requests and both rivets. */
export function getCombinedClassifier(): CombinedClassifier {
  if (!sharedClassifier) {
    sharedClassifier = new CombinedClassifier();
  }
  return sharedClassifier;
}

/** Test-only hook to inject a fake classifier for deterministic flag-mapping tests. */
export function setCombinedClassifierForTests(
  classifier: CombinedClassifier
): void {
  sharedClassifier = classifier;
}

/** Test-only hook to restore the default shared classifier. */
export function resetCombinedClassifierForTests(): void {
  sharedClassifier = null;
}
