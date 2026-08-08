import type { PromptChainmail } from "../index";

export enum ChainmailPreset {
  BASIC = "basic",
  ADVANCED = "advanced",
  DEVELOPMENT = "development",
  STRICT = "strict",
}

export type ChainmailPresetConfiguration = (
  maxLength?: number,
  confidenceFilter?: number
) => PromptChainmail;

export type ChainmailPresets = Record<
  ChainmailPreset,
  ChainmailPresetConfiguration
>;
