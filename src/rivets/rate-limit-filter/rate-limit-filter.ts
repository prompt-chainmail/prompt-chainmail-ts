import { ChainmailRivet } from "../../index";
import { SecurityFlags } from "../rivets.types";
import { ChainmailContext } from "../../types";

/**
 * @description
 * Quota filter. Sets `context.blocked` when the request cap is hit, not from
 * leftover trust. Detectors do not set `blocked`.
 */
export function rateLimitFilter(
  maxRequests = 100,
  windowMs = 60000,
  keyFn: (context: ChainmailContext) => string = () => "global",
  maxKeys = 1000
): ChainmailRivet {
  const requests = new Map<string, number[]>();

  return async (context, next) => {
    const key = keyFn(context);
    const now = Date.now();

    if (requests.size >= maxKeys && !requests.has(key)) {
      context.flags.add(SecurityFlags.RATE_LIMITED);
      context.blocked = true;
      return {
        success: false,
        context,
        processing_time: Date.now() - context.start_time,
      };
    }

    if (!requests.has(key)) {
      requests.set(key, []);
    }

    const timestamps = requests.get(key)!;

    while (timestamps.length > 0 && timestamps[0] < now - windowMs) {
      timestamps.shift();
    }

    if (timestamps.length >= maxRequests) {
      context.blocked = true;
      context.flags.add(SecurityFlags.RATE_LIMITED);
      return {
        success: false,
        context,
        processing_time: Date.now() - context.start_time,
      };
    }

    timestamps.push(now);
    return next();
  };
}
