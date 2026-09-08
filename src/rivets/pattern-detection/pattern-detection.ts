import { ChainmailRivet } from "../../index";
import { ThreatLevel, SecurityFlags } from "../rivets.types";
import { applyThreatPenalty } from "../rivets.utils";
import { createPatternDetectionPatterns } from "./pattern-detection.utils";

/**
 * @description
 * Detects malicious patterns using regex matching for injection attempts,
 * suspicious keywords, and attack signatures with custom pattern support.
 * Adds flags and a ThreatLevel penalty. Does not set `blocked`.
 */
export function patternDetection(customPatterns?: RegExp[]): ChainmailRivet {
  const patterns = [
    ...createPatternDetectionPatterns(),
    ...(customPatterns || []),
  ];

  return async (context, next) => {
    for (const pattern of patterns) {
      if (pattern.test(context.sanitized)) {
        context.flags.add(SecurityFlags.INJECTION_PATTERN);
        applyThreatPenalty(context, ThreatLevel.HIGH);
        context.metadata.matched_pattern = pattern.toString();
        break;
      }
    }
    return next();
  };
}
