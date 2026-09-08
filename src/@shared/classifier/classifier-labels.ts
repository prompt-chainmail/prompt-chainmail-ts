import { AttackType } from "../../rivets/instruction-hijacking/instruction-hijacking.types";
import { RoleConfusionAttackType } from "../../rivets/role-confusion/role-confusion.types";
import { ToolUseHijackingType } from "../../rivets/tool-use-hijacking/tool-use-hijacking.types";
import { SideChannelAttackType } from "../../rivets/side-channel/side-channel.types";

/**
 * Single source of truth for the classifier's label order. The order here
 * must exactly match `src/@shared/classifier/manifest.json`'s `labels` array
 * and the model's output tensor order.
 */
export const INSTRUCTION_HIJACKING_LABELS = Object.values(AttackType);
export const ROLE_CONFUSION_LABELS = Object.values(RoleConfusionAttackType);
export const TOOL_USE_HIJACKING_LABELS = Object.values(ToolUseHijackingType);
export const SIDE_CHANNEL_LABELS = Object.values(SideChannelAttackType);

export const CLASSIFIER_LABELS = [
  ...INSTRUCTION_HIJACKING_LABELS,
  ...ROLE_CONFUSION_LABELS,
  ...TOOL_USE_HIJACKING_LABELS,
  ...SIDE_CHANNEL_LABELS,
] as const;

export type ClassifierLabel = (typeof CLASSIFIER_LABELS)[number];

export type ClassifierFamily =
  | "instruction_hijacking"
  | "role_confusion"
  | "tool_use_hijacking"
  | "side_channel";

export function labelsForFamily(
  family: ClassifierFamily
): readonly ClassifierLabel[] {
  if (family === "instruction_hijacking") {
    return INSTRUCTION_HIJACKING_LABELS;
  }
  if (family === "role_confusion") {
    return ROLE_CONFUSION_LABELS;
  }
  if (family === "tool_use_hijacking") {
    return TOOL_USE_HIJACKING_LABELS;
  }
  return SIDE_CHANNEL_LABELS;
}
