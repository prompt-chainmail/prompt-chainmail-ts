import { SecurityFlags } from "../rivets.types";
import {
  detectLookalikeChars,
  hasLanguageScriptMixing,
  LanguageDetector,
} from "../../@shared/language-detection";
import { ChainmailContext, ChainmailRivet } from "../../types";
import { SideChannelDetector } from "./side-channel.utils";
import { SideChannelAttackType } from "./side-channel.types";
import { applyThreatPenalty } from "../rivets.utils";
import { ThreatLevel } from "../rivets.types";
import type { ClassifierMatch } from "../../@shared/classifier";

/**
 * @description
 * Detects unofficial side-channel use: peer coordination and durable shared-state
 * writes over wikis, pastes, signal pages, and similar out-of-band paths.
 * Uses the shared offline ONNX classifier.
 *
 * @param options Configuration options for side-channel detection
 * @param options.languagesLimit Maximum number of languages to report in metadata (default: 3)
 * @param options.languagesDetectionThreshold Minimum confidence threshold for language detection (default: 0.1)
 * @param options.confidenceThreshold Optional additional confidence floor on top of the classifier's
 *                                    per-label manifest thresholds. Omit to trust the manifest thresholds alone.
 */
export function sideChannel(
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
  const detector = new SideChannelDetector({
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

    const attackTypesArray = result.attack_types as SideChannelAttackType[];
    const maxConfidence = result.confidence;
    const maxRiskScore = result.risk_score;
    const allMatches: ClassifierMatch[] = result.matches ?? [];
    const isAttack = result.is_attack;

    if (isAttack) {
      context.flags.add(SecurityFlags.SIDE_CHANNEL);

      attackTypesArray.forEach((attackType) => {
        switch (attackType) {
          case SideChannelAttackType.COORDINATION:
            context.flags.add(SecurityFlags.SIDE_CHANNEL_COORDINATION);
            break;
          case SideChannelAttackType.STATE_WRITE:
            context.flags.add(SecurityFlags.SIDE_CHANNEL_STATE_WRITE);
            break;
        }
      });

      if (maxConfidence >= 0.4) {
        const threatLevel =
          maxConfidence > 0.7
            ? ThreatLevel.CRITICAL
            : maxConfidence > 0.5
              ? ThreatLevel.HIGH
              : ThreatLevel.MEDIUM;
        applyThreatPenalty(context, threatLevel);
      }

      context.metadata.side_channel_detected = true;
      context.metadata.side_channel_confidence = maxConfidence;
      context.metadata.side_channel_risk_score = maxRiskScore;
      context.metadata.side_channel_attack_types = attackTypesArray;
      context.metadata.side_channel_detected_language = primaryLanguage;
      context.metadata.side_channel_detected_languages = topLanguages.map(
        ([iso3]) => iso3
      );
      context.metadata.side_channel_matches = allMatches;
    } else {
      context.metadata.side_channel_detected = false;
      context.metadata.side_channel_confidence = maxConfidence;
      context.metadata.side_channel_risk_score = maxRiskScore;
      context.metadata.side_channel_attack_types = [];
      context.metadata.side_channel_detected_language = primaryLanguage;
      context.metadata.side_channel_detected_languages = topLanguages.map(
        ([iso3]) => iso3
      );
      context.metadata.side_channel_matches = allMatches;
    }

    context.metadata.has_script_mixing = hasScriptMixing;
    context.metadata.has_lookalikes = hasLookalikes;

    if (result.detector_error) {
      context.flags.add(SecurityFlags.CLASSIFIER_UNAVAILABLE);
      context.metadata.side_channel_detector_error = result.detector_error;
    }

    return next();
  };
}
