import { describe, it, expect } from "vitest";
import manifestJson from "./manifest.json" with { type: "json" };
import {
  CLASSIFIER_MANIFEST,
  ClassifierManifestError,
  validateManifest,
} from "./classifier-manifest";
import { CLASSIFIER_LABELS } from "./classifier-labels";
import { AttackType } from "../../rivets/instruction-hijacking/instruction-hijacking.types";
import { RoleConfusionAttackType } from "../../rivets/role-confusion/role-confusion.types";
import { ToolUseHijackingType } from "../../rivets/tool-use-hijacking/tool-use-hijacking.types";

describe("CLASSIFIER_LABELS", () => {
  it("orders instruction-hijacking labels before role-confusion labels before tool-use-hijacking", () => {
    expect(CLASSIFIER_LABELS).toEqual([
      AttackType.INSTRUCTION_OVERRIDE,
      AttackType.INSTRUCTION_FORGETTING,
      AttackType.RESET_SYSTEM,
      AttackType.BYPASS_SECURITY,
      AttackType.INFORMATION_EXTRACTION,
      RoleConfusionAttackType.ROLE_ASSUMPTION,
      RoleConfusionAttackType.MODE_SWITCHING,
      RoleConfusionAttackType.PERMISSION_ASSERTION,
      RoleConfusionAttackType.ROLE_INDICATOR,
      ToolUseHijackingType.TOOL_USE_HIJACKING,
    ]);
  });
});

describe("validateManifest", () => {
  it("accepts the committed development manifest", () => {
    expect(() => validateManifest(manifestJson)).not.toThrow();
    expect(CLASSIFIER_MANIFEST.labels).toEqual(CLASSIFIER_LABELS);
  });

  it("marks the committed manifest as an explicit non-release, development artifact", () => {
    expect(CLASSIFIER_MANIFEST.release_quality).toBe(false);
    expect(CLASSIFIER_MANIFEST.gate_failures.length).toBeGreaterThan(0);
  });

  it("rejects an unsupported schema_version", () => {
    const candidate = { ...manifestJson, schema_version: 2 };
    expect(() => validateManifest(candidate)).toThrow(ClassifierManifestError);
  });

  it("rejects labels out of order", () => {
    const candidate = {
      ...manifestJson,
      labels: [...CLASSIFIER_LABELS].reverse(),
    };
    expect(() => validateManifest(candidate)).toThrow(/labels/);
  });

  it("rejects a malformed model_sha256", () => {
    const candidate = { ...manifestJson, model_sha256: "not-hex" };
    expect(() => validateManifest(candidate)).toThrow(/model_sha256/);
  });

  it("rejects an oversized model_size_bytes", () => {
    const candidate = { ...manifestJson, model_size_bytes: 999 * 1024 * 1024 };
    expect(() => validateManifest(candidate)).toThrow(/model_size_bytes/);
  });

  it("rejects thresholds missing a required label", () => {
    const thresholds: Record<string, unknown> = { ...manifestJson.thresholds };
    delete thresholds.role_indicator;
    const candidate = { ...manifestJson, thresholds };
    expect(() => validateManifest(candidate)).toThrow(/thresholds/);
  });

  it("exposes the binary attack head's decision threshold", () => {
    expect(CLASSIFIER_MANIFEST.attack_threshold).toBeGreaterThan(0);
    expect(CLASSIFIER_MANIFEST.attack_threshold).toBeLessThanOrEqual(1);
  });

  it("rejects a missing attack_threshold", () => {
    const rest: Record<string, unknown> = { ...manifestJson };
    delete rest.attack_threshold;
    expect(() => validateManifest(rest)).toThrow(/attack_threshold/);
  });

  it("rejects an out-of-range attack_threshold", () => {
    const candidate = { ...manifestJson, attack_threshold: 1.5 };
    expect(() => validateManifest(candidate)).toThrow(/attack_threshold/);
  });

  it("rejects metrics missing the attack-head precision/recall/f1 fields", () => {
    const metrics: Record<string, unknown> = { ...manifestJson.metrics };
    delete metrics.attack_precision;
    const candidate = { ...manifestJson, metrics };
    expect(() => validateManifest(candidate)).toThrow(/metrics/);
  });

  it("accepts a FLOAT32 quantization format fallback", () => {
    const candidate = {
      ...manifestJson,
      quantization: { format: "FLOAT32", method: "none-float32-fallback" },
    };
    expect(() => validateManifest(candidate)).not.toThrow();
  });

  it("requires release_quality to be a boolean", () => {
    const rest: Record<string, unknown> = { ...manifestJson };
    delete rest.release_quality;
    expect(() => validateManifest(rest)).toThrow(/release_quality/);
  });

  it("rejects release_quality:false with empty gate_failures", () => {
    const candidate = {
      ...manifestJson,
      release_quality: false,
      gate_failures: [],
    };
    expect(() => validateManifest(candidate)).toThrow(/gate_failures/);
  });

  it("accepts release_quality:true with empty gate_failures", () => {
    const candidate = {
      ...manifestJson,
      release_quality: true,
      gate_failures: [],
    };
    expect(() => validateManifest(candidate)).not.toThrow();
  });
});
