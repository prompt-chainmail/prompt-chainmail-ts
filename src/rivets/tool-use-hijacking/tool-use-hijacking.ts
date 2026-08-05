import { SecurityFlags } from "../rivets.types";
import {
  detectLookalikeChars,
  hasLanguageScriptMixing,
  LanguageDetector,
} from "../../@shared/language-detection";
import { ChainmailContext, ChainmailRivet } from "../../types";
import { ToolHijackDetector } from "./tool-use-hijacking.utils";
import { applyThreatPenalty } from "../rivets.utils";
import { ThreatLevel } from "../rivets.types";
import type { ClassifierMatch } from "../../@shared/classifier";

/**
 * @description
 * Detects indirect tool-use hijacking attempts (exfiltration via agent tools,
 * covert email actions, integration abuse) using the shared offline ONNX
 * classifier.
 */
export function toolUseHijacking(
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
  const detector = new ToolHijackDetector({
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

    const maxConfidence = result.confidence;
    const maxRiskScore = result.risk_score;
    const allMatches: ClassifierMatch[] = result.matches ?? [];
    const isAttack = result.is_attack;

    if (isAttack) {
      context.flags.add(SecurityFlags.TOOL_USE_HIJACKING);

      if (maxConfidence >= 0.4) {
        const threatLevel =
          maxConfidence > 0.7
            ? ThreatLevel.CRITICAL
            : maxConfidence > 0.5
              ? ThreatLevel.HIGH
              : ThreatLevel.MEDIUM;
        applyThreatPenalty(context, threatLevel);
      }

      context.metadata.tool_use_hijacking_detected = true;
      context.metadata.tool_use_hijacking_confidence = maxConfidence;
      context.metadata.tool_use_hijacking_risk_score = maxRiskScore;
      context.metadata.tool_use_hijacking_attack_types = result.attack_types;
      context.metadata.tool_use_hijacking_detected_language = primaryLanguage;
      context.metadata.tool_use_hijacking_detected_languages = topLanguages.map(
        ([iso3]) => iso3
      );
      context.metadata.tool_use_hijacking_matches = allMatches;
    } else {
      context.metadata.tool_use_hijacking_detected = false;
      context.metadata.tool_use_hijacking_confidence = maxConfidence;
      context.metadata.tool_use_hijacking_risk_score = maxRiskScore;
      context.metadata.tool_use_hijacking_attack_types = [];
      context.metadata.tool_use_hijacking_detected_language = primaryLanguage;
      context.metadata.tool_use_hijacking_detected_languages = topLanguages.map(
        ([iso3]) => iso3
      );
      context.metadata.tool_use_hijacking_matches = allMatches;
    }

    context.metadata.has_script_mixing = hasScriptMixing;
    context.metadata.has_lookalikes = hasLookalikes;

    if (result.detector_error) {
      context.flags.add(SecurityFlags.CLASSIFIER_UNAVAILABLE);
      context.metadata.tool_use_hijacking_detector_error =
        result.detector_error;
    }

    return next();
  };
}
