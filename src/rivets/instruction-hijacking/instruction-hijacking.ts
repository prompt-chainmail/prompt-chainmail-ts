import { SecurityFlags } from "../rivets.types";
import {
  detectLookalikeChars,
  hasLanguageScriptMixing,
  LanguageDetector,
} from "../../@shared/language-detection";
import { ChainmailContext, ChainmailRivet } from "../../types";
import { IntrusionDetector } from "./instruction-hijacking.utils";
import { AttackType } from "./instruction-hijacking.types";
import { applyThreatPenalty } from "../rivets.utils";
import { ThreatLevel } from "../rivets.types";
import type { ClassifierMatch } from "../../@shared/classifier";

/**
 * @description
 * Analyzes the content within the provided context to detect and mitigate possible instruction hijacking attacks.
 * Uses an offline, multilingual byte-level ONNX classifier (see `src/@shared/classifier`) instead of pattern
 * matching or vector search. It tries to identify relevant languages in the content for metadata and risk
 * weighting, classifies the sanitized text once, and applies appropriate security flags and threat penalties
 * based on the classification.
 *
 * @param options Configuration options for instruction hijacking detection
 * @param options.languagesLimit Maximum number of languages to report in metadata (default: 3)
 * @param options.languagesDetectionThreshold Minimum confidence threshold for language detection (default: 0.1)
 * @param options.confidenceThreshold Optional additional confidence floor on top of the classifier's
 *                                    per-label manifest thresholds. Omit to trust the manifest thresholds alone.
 */
export function instructionHijacking(
  options: {
    languagesLimit?: number;
    languagesDetectionThreshold?: number;
    confidenceThreshold?: number;
  } = {}
): ChainmailRivet {
  const languageDetector = new LanguageDetector();
  const defaultLanguage = "eng";
  const languagesDetectionThreshold =
    options.languagesDetectionThreshold ?? 0.1;
  const languagesLimit = options.languagesLimit ?? 3;
  const intrusionDetector = new IntrusionDetector({
    confidenceThreshold: options.confidenceThreshold,
  });

  return async (context: ChainmailContext, next) => {
    if (!context.input.trim()) {
      return next();
    }
    const languages = languageDetector
      .detect(context.input)
      .filter(([, confidence]) => confidence > languagesDetectionThreshold);

    if (languages.length === 0) {
      languages.push([defaultLanguage, 0.1]);
    }

    const topLanguages = languages.slice(0, languagesLimit);
    const hasScriptMixing = hasLanguageScriptMixing(context.sanitized);
    const hasLookalikes = detectLookalikeChars(context.sanitized);
    const [primaryLanguage] = topLanguages[0];

    const result = await intrusionDetector.detect(
      context.sanitized,
      primaryLanguage
    );

    const attackTypesArray = result.attack_types as AttackType[];
    const maxConfidence = result.confidence;
    const maxRiskScore = result.risk_score;
    const allMatches: ClassifierMatch[] = result.matches ?? [];
    const isAttack = result.is_attack;

    if (isAttack) {
      const flagSet = new Set<SecurityFlags>();

      flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING);

      attackTypesArray.forEach((attackType) => {
        switch (attackType) {
          case AttackType.INSTRUCTION_OVERRIDE:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_OVERRIDE);
            break;
          case AttackType.INSTRUCTION_FORGETTING:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_IGNORE);
            break;
          case AttackType.RESET_SYSTEM:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_RESET);
            break;
          case AttackType.BYPASS_SECURITY:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_BYPASS);
            break;
          case AttackType.INFORMATION_EXTRACTION:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_REVEAL);
            break;
          default:
            flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_UNKNOWN);
        }
      });

      if (languages.length > 1) {
        flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_MULTILINGUAL_ATTACK);
      }

      if (hasScriptMixing) {
        flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_SCRIPT_MIXING);
      }

      if (hasLookalikes) {
        flagSet.add(SecurityFlags.INSTRUCTION_HIJACKING_LOOKALIKES);
      }

      flagSet.forEach((flag) => context.flags.add(flag));

      // Only apply penalties for higher confidence detections to reduce false positives
      // Low confidence matches are flagged but not penalized
      if (maxConfidence >= 0.4) {
        const threatLevel =
          maxConfidence > 0.7
            ? ThreatLevel.CRITICAL
            : maxConfidence > 0.5
              ? ThreatLevel.HIGH
              : ThreatLevel.MEDIUM;

        applyThreatPenalty(context, threatLevel);
      }

      context.metadata.instruction_hijacking_detected = true;
      context.metadata.instruction_hijacking_confidence = maxConfidence;
      context.metadata.instruction_hijacking_risk_score = maxRiskScore;
      context.metadata.instruction_hijacking_attack_types = attackTypesArray;
      context.metadata.instruction_hijacking_detected_language =
        primaryLanguage;
      context.metadata.instruction_hijacking_detected_languages =
        topLanguages.map(([iso3]) => iso3);
      context.metadata.instruction_hijacking_matches = allMatches;
    } else {
      context.metadata.instruction_hijacking_detected = false;
      context.metadata.instruction_hijacking_confidence = maxConfidence;
      context.metadata.instruction_hijacking_risk_score = maxRiskScore;
      context.metadata.instruction_hijacking_attack_types = [];
      context.metadata.instruction_hijacking_detected_language =
        primaryLanguage;
      context.metadata.instruction_hijacking_detected_languages =
        topLanguages.map(([iso3]) => iso3);
      context.metadata.instruction_hijacking_matches = allMatches;
    }

    context.metadata.has_script_mixing = hasScriptMixing;
    context.metadata.has_lookalikes = hasLookalikes;

    if (result.detector_error) {
      // Fail-open (detection never blocks on an unavailable classifier),
      // but the failure must stay distinguishable from a genuinely clean
      // input via a dedicated flag + safe error code metadata.
      context.flags.add(SecurityFlags.CLASSIFIER_UNAVAILABLE);
      context.metadata.instruction_hijacking_detector_error =
        result.detector_error;
    }

    return next();
  };
}
