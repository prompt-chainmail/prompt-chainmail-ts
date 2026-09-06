import { ChainmailRivet } from "../../index";

/**
 * @description
 * Trust gate. This is the rivet that sets `context.blocked` from leftover
 * confidence. Detectors only add flags and subtract trust; if this rivet is
 * not forged, flags stay and `blocked` stays false.
 * When only minThreshold is provided, blocks when confidence is strictly
 * below the threshold. When both are provided, blocks inside the range.
 *
 * @param minThreshold Minimum confidence threshold (default: 0.5)
 * @param maxThreshold Optional maximum confidence threshold for range filtering
 */
export function confidenceFilter(
  minThreshold = 0.5,
  maxThreshold?: number
): ChainmailRivet {
  return async (context, next) => {
    const shouldBlock = maxThreshold
      ? context.confidence >= minThreshold && context.confidence <= maxThreshold
      : context.confidence < minThreshold;

    if (shouldBlock) {
      context.blocked = true;
    }

    return next();
  };
}
