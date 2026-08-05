import { describe, vi } from "vitest";
import { PromptChainmail } from "../../index";
import { protectBench } from "../../@shared/benchmark.utils";
import { telemetry } from "./telemetry";
import type { TelemetryProvider } from "./telemetry.types";

describe("telemetry()", () => {
  const mockProvider: TelemetryProvider = {
    logSecurityEvent: vi.fn(),
    trackMetric: vi.fn(),
    captureError: vi.fn(),
    addBreadcrumb: vi.fn(),
  };

  const chainmail = new PromptChainmail().forge(
    telemetry({ provider: mockProvider, logFn: () => undefined })
  );

  protectBench("simple", chainmail, "test input");
  protectBench(
    "signal",
    chainmail,
    "This is a longer telemetry path input for benchmarking."
  );
});
