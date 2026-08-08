/**
 * Threat levels for security violations
 */
export enum ThreatLevel {
  LOW = 0.1,
  MEDIUM = 0.25,
  HIGH = 0.4,
  CRITICAL = 0.6,
}

/**
 * Standard security flags used by default rivets
 * Organized from general to specific attack types
 */
export enum SecurityFlags {
  // General content processing
  TRUNCATED = "truncated",
  UNTRUSTED_WRAPPED = "untrusted_wrapped",

  //Sanitization
  SANITIZED_HTML_TAGS = "sanitized_html_tags",
  SANITIZED_CONTROL_CHARS = "sanitized_control_chars",
  SANITIZED_WHITESPACE = "sanitized_whitespace",

  // General pattern detection
  INJECTION_PATTERN = "injection_pattern",

  // General structure analysis
  EXCESSIVE_LINES = "excessive_lines",
  NON_ASCII_HEAVY = "non_ascii_heavy",
  REPETITIVE_CONTENT = "repetitive_content",

  // General encoding detection
  BASE64_ENCODING = "base64_encoding",
  HEX_ENCODING = "hex_encoding",
  URL_ENCODING = "url_encoding",
  UNICODE_ENCODING = "unicode_encoding",
  HTML_ENTITY_ENCODING = "html_entity_encoding",
  BINARY_ENCODING = "binary_encoding",
  OCTAL_ENCODING = "octal_encoding",
  ROT13_ENCODING = "rot13_encoding",
  MIXED_CASE_OBFUSCATION = "mixed_case_obfuscation",

  // General rate control
  RATE_LIMITED = "rate_limited",

  // Classifier-backed detector availability (family-neutral: applies to
  // both role_confusion and instruction_hijacking)
  CLASSIFIER_UNAVAILABLE = "classifier_unavailable",

  // General HTTP operations
  HTTP_VALIDATION_FAILED = "http_validation_failed",
  HTTP_SUCCESS = "http_success",
  HTTP_ERROR = "http_error",
  HTTP_TIMEOUT = "http_timeout",

  // Specific injection attacks
  SQL_INJECTION = "sql_injection",
  CODE_INJECTION = "code_injection",
  TEMPLATE_INJECTION = "template_injection",
  DELIMITER_CONFUSION = "delimiter_confusion",
  TOOL_USE_HIJACKING = "tool_use_hijacking",

  // Specific role confusion attacks
  ROLE_CONFUSION = "role_confusion",
  ROLE_CONFUSION_ROLE_ASSUMPTION = "role_confusion_role_assumption",
  ROLE_CONFUSION_MODE_SWITCHING = "role_confusion_mode_switching",
  ROLE_CONFUSION_PERMISSION_ASSERTION = "role_confusion_permission_assertion",
  ROLE_CONFUSION_ROLE_INDICATOR = "role_confusion_role_indicator",
  ROLE_CONFUSION_SCRIPT_MIXING = "role_confusion_script_mixing",
  ROLE_CONFUSION_LOOKALIKE_CHARACTERS = "role_confusion_lookalike_characters",
  ROLE_CONFUSION_MULTILINGUAL_ATTACK = "role_confusion_multilingual_attack",
  ROLE_CONFUSION_HIGH_RISK_ROLE = "role_confusion_high_risk_role",

  // Specific instruction hijacking attacks
  INSTRUCTION_HIJACKING = "instruction_hijacking",
  INSTRUCTION_HIJACKING_OVERRIDE = "instruction_hijacking_override",
  INSTRUCTION_HIJACKING_IGNORE = "instruction_hijacking_ignore",
  INSTRUCTION_HIJACKING_RESET = "instruction_hijacking_reset",
  INSTRUCTION_HIJACKING_BYPASS = "instruction_hijacking_bypass",
  INSTRUCTION_HIJACKING_REVEAL = "instruction_hijacking_reveal",
  INSTRUCTION_HIJACKING_UNKNOWN = "instruction_hijacking_unknown",
  INSTRUCTION_HIJACKING_SCRIPT_MIXING = "instruction_hijacking_script_mixing",
  INSTRUCTION_HIJACKING_LOOKALIKES = "instruction_hijacking_lookalikes",
  INSTRUCTION_HIJACKING_MULTILINGUAL_ATTACK = "instruction_hijacking_multilingual_attack",
}
