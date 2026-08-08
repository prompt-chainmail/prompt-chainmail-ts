import cybercrimeIndex from "../../@configs/language_region_cybercrime_index.json" with { type: "json" };
import languageGroups from "../../@configs/language_iso3_to_language_groups.json" with { type: "json" };
import { RiskCalculationConfig } from "./classifier.types";

let cachedCybercrimeValues: number[] | null = null;
let cachedFifthHighestThreshold: number | null = null;
let languageCodeMap: Map<string, string> | null = null;

function ensureCybercrimeCache(): void {
  if (cachedCybercrimeValues !== null) {
    return;
  }
  const values = Object.values(cybercrimeIndex.value) as number[];
  cachedCybercrimeValues = [...values].sort((a, b) => b - a);
  cachedFifthHighestThreshold = cachedCybercrimeValues[4] || 0;
}

function ensureLanguageGroupCache(): void {
  if (languageCodeMap !== null) {
    return;
  }
  languageCodeMap = new Map();
  for (const [key, value] of Object.entries(languageGroups.value)) {
    languageCodeMap.set(key, value as string);
  }
}

export function languageGroupForCode(languageCode: string): string {
  ensureLanguageGroupCache();
  return languageCodeMap?.get(languageCode) || "eng";
}

/**
 * Weights raw classifier confidence by the target language's cybercrime
 * index and the number of distinct attack types detected. Ported unchanged
 * from the removed vector-search semantic detector.
 */
export function calculateLanguageCodeRiskScore(
  confidence: number,
  languageGroup: string,
  attackTypeCount: number,
  config: RiskCalculationConfig
): number {
  ensureCybercrimeCache();

  const {
    cybercrime_index_base,
    max_attack_type_multiplier,
    attack_type_divisor,
    high_risk_boost,
    max_risk_score,
    fallback_threshold,
  } = config;

  const baseRisk = confidence * 100;

  const cybercrimeIndexValue =
    (cybercrimeIndex.value as Record<string, number>)[languageGroup] ||
    cybercrime_index_base;
  const cybercrimeMultiplier = cybercrimeIndexValue / cybercrime_index_base;
  const calculatedMultiplier = attackTypeCount / attack_type_divisor;
  const attackTypeMultiplier =
    calculatedMultiplier < max_attack_type_multiplier
      ? calculatedMultiplier
      : max_attack_type_multiplier;

  const fifthHighestThreshold =
    cachedFifthHighestThreshold || fallback_threshold || 50;

  const riskBoost =
    attackTypeCount > 1 && cybercrimeIndexValue >= fifthHighestThreshold
      ? high_risk_boost
      : 1;

  const riskScore =
    baseRisk * cybercrimeMultiplier * (1 + attackTypeMultiplier) * riskBoost;
  return riskScore < max_risk_score ? riskScore : max_risk_score;
}
