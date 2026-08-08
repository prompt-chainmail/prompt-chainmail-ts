import { SecurityFlags } from "../rivets.types";
import {
  hasLanguageScriptMixing,
  detectLookalikeChars,
  LanguageDetector,
} from "../../@shared/language-detection";
import { RoleConfusionDetector } from "./role-confusion.utils";
import { ChainmailContext, ChainmailRivet } from "../../types";
import { applyThreatPenalty } from "../rivets.utils";
import { ThreatLevel } from "../rivets.types";
import { RoleConfusionAttackType } from "./role-confusion.types";
import type { ClassifierMatch } from "../../@shared/classifier";

/**
 * @description
 * Analyzes the content within the provided context to detect and mitigate possible role confusion attacks.
 * Uses an offline, multilingual byte-level ONNX classifier (see `src/@shared/classifier`) instead of pattern
 * matching or vector search. It tries to identify relevant languages in the content for metadata and risk
 * weighting, classifies the sanitized text once, and applies appropriate security flags and threat penalties
 * based on the classification.
 *
 * @param options Configuration options for role confusion detection
 * @param options.languagesLimit Maximum number of languages to report in metadata (default: 3)
 * @param options.languagesDetectionThreshold Minimum confidence threshold for language detection (default: 0.6)
 * @param options.confidenceThreshold Optional additional confidence floor on top of the classifier's
 *                                    per-label manifest thresholds. Omit to trust the manifest thresholds alone.
 */
export function roleConfusion(
  options: {
    languagesLimit?: number;
    languagesDetectionThreshold?: number;
    confidenceThreshold?: number;
  } = {}
): ChainmailRivet {
  const languageDetector = new LanguageDetector();
  const languagesLimit = options.languagesLimit ?? 3;
  const languagesDetectionThreshold =
    options.languagesDetectionThreshold ?? 0.6;
  const defaultLanguage = "eng";
  const highRiskRoleConfidenceThreshold = 0.7;
  const detector = new RoleConfusionDetector({
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

    const result = await detector.detect(context.sanitized, primaryLanguage);

    const attackTypesArray = result.attack_types as RoleConfusionAttackType[];
    const maxConfidence = result.confidence;
    const maxRiskScore = result.risk_score;
    const allMatches: ClassifierMatch[] = result.matches ?? [];
    const isAttack = result.is_attack;

    if (isAttack) {
      const flagSet = new Set(context.flags);

      flagSet.add(SecurityFlags.ROLE_CONFUSION);

      attackTypesArray.forEach((attackType: RoleConfusionAttackType) => {
        switch (attackType) {
          case RoleConfusionAttackType.ROLE_ASSUMPTION:
            flagSet.add(SecurityFlags.ROLE_CONFUSION_ROLE_ASSUMPTION);
            break;
          case RoleConfusionAttackType.MODE_SWITCHING:
            flagSet.add(SecurityFlags.ROLE_CONFUSION_MODE_SWITCHING);
            break;
          case RoleConfusionAttackType.PERMISSION_ASSERTION:
            flagSet.add(SecurityFlags.ROLE_CONFUSION_PERMISSION_ASSERTION);
            break;
          case RoleConfusionAttackType.ROLE_INDICATOR:
            flagSet.add(SecurityFlags.ROLE_CONFUSION_ROLE_INDICATOR);
            break;
        }
      });

      if (
        maxConfidence > highRiskRoleConfidenceThreshold &&
        attackTypesArray.length > 1
      ) {
        flagSet.add(SecurityFlags.ROLE_CONFUSION_HIGH_RISK_ROLE);
      }

      if (languages.length > 1) {
        flagSet.add(SecurityFlags.ROLE_CONFUSION_MULTILINGUAL_ATTACK);
      }

      if (hasScriptMixing) {
        flagSet.add(SecurityFlags.ROLE_CONFUSION_SCRIPT_MIXING);
      }

      if (hasLookalikes) {
        flagSet.add(SecurityFlags.ROLE_CONFUSION_LOOKALIKE_CHARACTERS);
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

      context.metadata.role_confusion_detected = true;
      context.metadata.role_confusion_attack_types = attackTypesArray;
    } else {
      context.metadata.role_confusion_detected = false;
      context.metadata.role_confusion_attack_types = [];
    }

    context.metadata.role_confusion_confidence = maxConfidence;
    context.metadata.role_confusion_risk_score = maxRiskScore;
    context.metadata.role_confusion_dominant_language = primaryLanguage;
    context.metadata.role_confusion_detected_languages = topLanguages.map(
      ([iso3]) => iso3
    );
    context.metadata.role_confusion_matches = allMatches;
    context.metadata.has_script_mixing = hasScriptMixing;
    context.metadata.has_lookalikes = hasLookalikes;

    if (result.detector_error) {
      // Fail-open (detection never blocks on an unavailable classifier),
      // but the failure must stay distinguishable from a genuinely clean
      // input via a dedicated flag + safe error code metadata.
      context.flags.add(SecurityFlags.CLASSIFIER_UNAVAILABLE);
      context.metadata.role_confusion_detector_error = result.detector_error;
    }

    return next();
  };
}
