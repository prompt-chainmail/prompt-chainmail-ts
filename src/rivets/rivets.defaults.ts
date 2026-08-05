import { sanitize } from "./sanitize/sanitize";
import { patternDetection } from "./pattern-detection/pattern-detection";
import { roleConfusion } from "./role-confusion/role-confusion";
import { encodingDetection } from "./encoding-detection/encoding-detection";
import { sqlInjection } from "./sql-injection/sql-injection";
import { codeInjection } from "./code-injection/code-injection";
import { delimiterConfusion } from "./delimiter-confusion/delimiter-confusion";
import { instructionHijacking } from "./instruction-hijacking/instruction-hijacking";
import { toolUseHijacking } from "./tool-use-hijacking/tool-use-hijacking";
import { templateInjection } from "./template-injection/template-injection";
import { structureAnalysis } from "./structure-analysis/structure-analysis";
import { confidenceFilter } from "./confidence-filter/confidence-filter";
import { rateLimit } from "./rate-limit/rate-limit";
import { logger } from "./logger/logger";
import { untrustedWrapper } from "./untrusted-wrapper/untrusted-wrapper";
import { httpFetch } from "./http-fetch/http-fetch";
import { condition } from "./condition/condition";
import { telemetry } from "./telemetry/telemetry";
import { languageDetection } from "./language-detection/language-detection";

export const Rivets = {
  sanitize,
  patternDetection,
  roleConfusion,
  encodingDetection,
  languageDetection,
  sqlInjection,
  codeInjection,
  delimiterConfusion,
  instructionHijacking,
  toolUseHijacking,
  templateInjection,
  structureAnalysis,
  confidenceFilter,
  rateLimit,
  logger,
  untrustedWrapper,
  httpFetch,
  condition,
  telemetry,
};
