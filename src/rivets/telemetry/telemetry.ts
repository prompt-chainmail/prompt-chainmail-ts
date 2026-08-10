import type { ChainmailRivet } from "../../index";
import { LogLevel } from "vite";
import {
  TelemetryData,
  TelemetryEventType,
  TelemetryOptions,
} from "./telemetry.types";
import { SecurityFlags, ThreatLevel } from "../rivets.types";
import {
  getLogLevelFromConfidence,
  getThreatLevelFromConfidenceScore,
  validateProvider,
} from "./telemetry.utils";

/**
 * @description
 * Implements a telemetry system for monitoring and logging operational metrics, errors, and security events within a processing pipeline.
 */
export function telemetry(options: TelemetryOptions = {}): ChainmailRivet {
  const {
    logFn = (level, message, data) => {
      const logLevel =
        level === "error" ? "error" : level === "warn" ? "warn" : "info";
      console[logLevel]("[PromptChainmail]", message, data);
    },
    track_metrics = true,
    logErrors = true,
    provider,
  } = options;

  const telemetryProvider =
    provider && validateProvider(provider) ? provider : null;

  return async (context, next) => {
    const startTime = Date.now();

    telemetryProvider?.addBreadcrumb("Processing started", {
      session_id: context.session_id,
      input_length: context.input.length,
    });

    try {
      const result = await next();
      const processingTime = Date.now() - startTime;

      const telemetryData: TelemetryData = {
        session_id: context.session_id,
        flags: Array.from(context.flags),
        confidence: context.confidence,
        processing_time: processingTime,
        input_length: context.input.length,
        blocked: context.blocked,
        success: result.success,
      };

      if (telemetryProvider) {
        telemetryProvider.trackMetric("processing_time", processingTime, {
          success: result.success.toString(),
          flags_count: context.flags.size.toString(),
        });

        if (!result.success || context.flags.size > 0) {
          const threatLevel = getThreatLevelFromConfidenceScore(
            context.confidence
          );
          const eventType = context.blocked
            ? TelemetryEventType.THREAT_BLOCKED
            : context.flags.size > 0
              ? TelemetryEventType.THREAT_DETECTED
              : TelemetryEventType.SECURITY_SCAN;

          telemetryProvider.logSecurityEvent({
            type: eventType,
            threat_level: threatLevel,
            message: `Security check ${result.success ? "passed" : "failed"}: ${Array.from(context.flags).join(", ")}`,
            context: telemetryData,
            flags: Array.from(context.flags) as SecurityFlags[],
            risk_score: (context.metadata?.risk_score ?? undefined) as number,
            attack_types: (context.metadata?.attack_types ??
              undefined) as string[],
          });
        }
      }

      if (!telemetryProvider && track_metrics) {
        logFn(
          "info",
          `Processing completed in ${processingTime}ms`,
          telemetryData
        );

        if (!result.success || context.flags.size > 0) {
          const level: LogLevel = getLogLevelFromConfidence(context.confidence);

          logFn(
            level,
            `Security flags detected: ${Array.from(context.flags).join(", ")}`,
            telemetryData
          );
        }
      }

      return result;
    } catch (error) {
      const processingTime = Date.now() - startTime;

      const telemetryData: TelemetryData = {
        session_id: context.session_id,
        flags: Array.from(context.flags),
        confidence: context.confidence,
        processing_time: processingTime,
        input_length: context.input.length,
        blocked: context.blocked,
        success: false,
      };

      if (telemetryProvider) {
        telemetryProvider.captureError(
          error as Error,
          telemetryData as Record<string, unknown>
        );
        telemetryProvider.logSecurityEvent({
          type: TelemetryEventType.PROCESSING_ERROR,
          threat_level: ThreatLevel.LOW,
          message: `Processing failed: ${(error as Error).message}`,
          context: telemetryData,
        });
      }

      if (!telemetryProvider && logErrors) {
        logFn(
          "error",
          `Processing failed: ${(error as Error).message}`,
          telemetryData
        );
      }

      throw error;
    }
  };
}
