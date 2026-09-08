/**
 * Context object passed through the rivet chain during input processing.
 * Contains the current state of input analysis and security assessment.
 *
 * @public
 * @example Processing Context
 * @example Custom gate rivet (not a detector)
 * ```typescript
 * const rivet: ChainmailRivet = async (context, next) => {
 *   if (context.confidence < 0.5) {
 *     context.blocked = true;
 *     context.metadata.reason = 'Confidence below threshold';
 *   }
 *   return next();
 * };
 * ```
 */
export interface ChainmailContext {
  /** Original input text or stream summary (readonly after initialization) */
  readonly input: string;
  /** Current processed text after rivet transformations */
  sanitized: string;
  /** Security flags detected during processing (e.g., 'role_confusion', 'sql_injection') */
  flags: Set<string>;
  /**
   * Security confidence score (0.0 to 1.0):
   * - 1.0: No threats detected, completely safe
   * - 0.9: Low threat penalty applied (0.1 deduction)
   * - 0.75: Medium threat penalty applied (0.25 deduction)
   * - 0.6: High threat penalty applied (0.4 deduction)
   * - 0.4: Critical threat penalty applied (0.6 deduction)
   * - 0.0: Multiple critical threats, maximum penalty
   */
  confidence: number;
  /** Additional data from rivets (patterns matched, decoded content, etc.) */
  metadata: Record<string, unknown>;
  /**
   * True only if a forged rivet set it (`confidenceFilter` or
   * `rateLimitFilter`). Detectors never set this.
   */
  blocked: boolean;
  /** Timestamp when processing started (milliseconds since epoch) */
  readonly start_time: number;
  /** Unique session identifier for tracking and debugging */
  readonly session_id: string;
}

/**
 * Result object returned after processing input through the chainmail.
 * Contains success status, processing context, and any errors encountered.
 *
 * @public
 * @example Handling Results
 * ```typescript
 * const result = await chainmail.protect(userInput);
 *
 * if (result.success) {
 *   // Safe to process
 *   await processInput(result.context.sanitized);
 * } else {
 *   // Handle security violation
 *   logger.warn('Security violation', {
 *     flags: result.context.flags,
 *     confidence: result.context.confidence
 *   });
 * }
 * ```
 */
export interface ChainmailResult {
  /** Whether the input passed all security checks */
  success: boolean;
  /** Processing context containing analysis results */
  context: ChainmailContext;
  /** Error message if processing failed */
  error?: string;
  /** Processing duration in milliseconds */
  processing_time: number;
  /** Memory usage during processing in bytes */
  memory_usage?: number;
}

/**
 * A rivet function that processes input context and can modify it.
 * Rivets are chained together to form a complete security pipeline.
 *
 * @param context - The current processing context
 * @param next - Function to call the next rivet in the chain
 * @returns Promise resolving to the processing result
 *
 * @public
 * @example Custom Rivet
 * ```typescript
 * const customRivet: ChainmailRivet = async (context, next) => {
 *   // Pre-processing logic
 *   if (context.sanitized.includes('forbidden')) {
 *     context.flags.add('forbidden_content');
 *     context.confidence *= 0.5;
 *   }
 *
 *   // Continue to next rivet
 *   const result = await next();
 *
 *   // Post-processing logic
 *   if (!result.success) {
 *     context.metadata.failure_reason = 'Custom rivet detected issue';
 *   }
 *
 *   return result;
 * };
 * ```
 */
export type ChainmailRivet = (
  context: ChainmailContext,
  next: () => Promise<ChainmailResult>
) => Promise<ChainmailResult>;
