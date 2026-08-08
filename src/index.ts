import {
  Rivets,
  applyThreatPenalty,
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
} from "./rivets/index";
import { Chainmails } from "./chainmails/index";
import { toChunks } from "./utils";
import { ChainmailContext, ChainmailResult, ChainmailRivet } from "./types";

export { Rivets, Chainmails, applyThreatPenalty };

export {
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

export type { ChainmailRivet };

const MAX_INPUT_SIZE_IN_MB = 1024 * 1024 * 2;
const STRING_CHUNKING_THRESHOLD = 64 * 1024;
const MAX_CHUNK_SIZE = 4096;

/**
 * Core chainmail class for forging security rivets
 *
 * @example
 * ```typescript
 * const chainmail = new PromptChainmail()
 *   .forge(Rivets.sanitize())
 *   .forge(Rivets.patternDetection())
 *   .forge(Rivets.confidenceFilter(0.7));
 *
 * const result = await chainmail.protect(userInput);
 * ```
 */
export class PromptChainmail {
  private rivets: Set<ChainmailRivet> = new Set();

  /**
   * Forge a new rivet into the chainmail
   */
  forge(rivet: ChainmailRivet): this {
    if (this.rivets.has(rivet)) {
      throw new Error(
        "Duplicate rivet: This rivet has already been forged into the chainmail"
      );
    }

    this.rivets.add(rivet);
    return this;
  }

  /**
   * Protect input by running it through all forged rivets
   */
  async protect(
    input: string | ReadableStream | ArrayBuffer | Uint8Array
  ): Promise<ChainmailResult> {
    const startTime = Date.now();
    const sessionId = crypto.randomUUID();

    if (input == null) {
      const processingTime = Date.now() - startTime;
      const context: ChainmailContext = {
        input: "",
        sanitized: "",
        flags: new Set(["invalid_input"]),
        blocked: true,
        start_time: startTime,
        session_id: sessionId,
        confidence: 1,
        metadata: {},
      };
      return this.createResult(
        context,
        processingTime,
        `Invalid input: ${input}`
      );
    }

    if (typeof input === "string") {
      if (input.length > STRING_CHUNKING_THRESHOLD) {
        const stream = this.stringToStream(input);
        return this.protectStream(stream, startTime, sessionId);
      }

      return this.protectString(input, startTime, sessionId);
    }
    return this.protectStream(input, startTime, sessionId);
  }

  /**
   * Convert a large string to ReadableStream for chunked processing
   */
  private stringToStream(input: string): ReadableStream<Uint8Array> {
    return new ReadableStream({
      start(controller) {
        const encoder = new TextEncoder();
        let offset = 0;

        while (offset < input.length) {
          const chunk = input.slice(offset, offset + MAX_CHUNK_SIZE);
          controller.enqueue(encoder.encode(chunk));
          offset += MAX_CHUNK_SIZE;
        }
        controller.close();
      },
    });
  }

  /**
   * Protect string input (original implementation)
   */
  private async protectString(
    input: string,
    startTime: number,
    sessionId: string
  ): Promise<ChainmailResult> {
    const context: ChainmailContext = {
      input,
      sanitized: input,
      flags: new Set(),
      confidence: 1.0,
      metadata: {},
      blocked: false,
      start_time: startTime,
      session_id: sessionId,
    };

    if (this.rivets.size === 0) {
      return this.createResult(context, Date.now() - startTime);
    }

    let index = 0;
    const rivetArray = Array.from(this.rivets);
    const next = async (): Promise<ChainmailResult> => {
      if (index >= rivetArray.length) {
        return this.createResult(context, Date.now() - startTime);
      }

      const rivet = rivetArray[index++];
      const protectedContext = this.createContext(context);

      return await rivet(protectedContext, next);
    };

    try {
      return await next();
    } catch (error) {
      context.blocked = true;
      return this.createResult(
        context,
        Date.now() - startTime,
        error instanceof Error ? error.message : "Unknown error"
      );
    }
  }

  /**
   * Protect streaming input by processing chunks
   */
  private async protectStream(
    input: ReadableStream | ArrayBuffer | Uint8Array,
    startTime: number,
    sessionId: string
  ): Promise<ChainmailResult> {
    let chunkCount = 0;
    let totalLength = 0;
    const streamFlagsSet = new Set<string>();
    const streamMetadata: Record<string, unknown> = Object.create(null);
    let minConfidence = 1.0;

    try {
      for await (const chunk of toChunks(input, MAX_CHUNK_SIZE)) {
        chunkCount++;
        totalLength += chunk.length;

        if (totalLength > MAX_INPUT_SIZE_IN_MB) {
          streamFlagsSet.add("stream_size_exceeded");
          streamMetadata.stream_size_limit = MAX_INPUT_SIZE_IN_MB;
          return this.createStreamResult(
            true,
            chunkCount,
            totalLength,
            Array.from(streamFlagsSet),
            streamMetadata,
            0,
            startTime,
            sessionId
          );
        }

        const chunkContext: ChainmailContext = {
          input: chunk,
          sanitized: chunk,
          flags: new Set(),
          confidence: 1.0,
          metadata: {},
          blocked: false,
          start_time: startTime,
          session_id: sessionId,
        };

        const chunkResult = await this.processChunkThroughRivets(
          chunkContext,
          startTime
        );

        chunkResult.context.flags.forEach((flag) => streamFlagsSet.add(flag));
        Object.assign(streamMetadata, chunkResult.context.metadata);
        minConfidence = Math.min(minConfidence, chunkResult.context.confidence);

        if (chunkResult.context.blocked) {
          return this.createStreamResult(
            true,
            chunkCount,
            totalLength,
            Array.from(streamFlagsSet),
            streamMetadata,
            minConfidence,
            startTime,
            sessionId
          );
        }
      }

      return this.createStreamResult(
        false,
        chunkCount,
        totalLength,
        Array.from(streamFlagsSet),
        streamMetadata,
        minConfidence,
        startTime,
        sessionId
      );
    } catch (error) {
      streamFlagsSet.add("stream_processing_error");
      streamMetadata.streamError =
        error instanceof Error ? error.message : "Unknown stream error";
      return this.createStreamResult(
        true,
        chunkCount,
        totalLength,
        Array.from(streamFlagsSet),
        streamMetadata,
        0,
        startTime,
        sessionId
      );
    }
  }

  private async processChunkThroughRivets(
    chunkContext: ChainmailContext,
    startTime: number
  ): Promise<ChainmailResult> {
    if (this.rivets.size === 0) {
      return this.createResult(chunkContext, Date.now() - startTime);
    }

    const rivetArray = Array.from(this.rivets);
    let index = 0;
    const next = async (): Promise<ChainmailResult> => {
      if (index >= rivetArray.length) {
        return this.createResult(chunkContext, Date.now() - startTime);
      }
      const rivet = rivetArray[index++];
      const protectedContext = this.createContext(chunkContext);
      return rivet(protectedContext, next);
    };
    return next();
  }

  private createStreamResult(
    blocked: boolean,
    chunkCount: number,
    totalLength: number,
    streamFlags: string[],
    streamMetadata: Record<string, unknown>,
    confidence: number,
    startTime: number,
    sessionId: string
  ): ChainmailResult {
    streamMetadata.chunk_count = chunkCount;
    streamMetadata.total_length = totalLength;

    const streamDesc = `[Stream: ${chunkCount} chunks, ${totalLength} chars]`;
    const finalContext: ChainmailContext = {
      input: streamDesc,
      sanitized: streamDesc,
      flags: new Set(streamFlags),
      confidence,
      metadata: streamMetadata,
      blocked,
      start_time: startTime,
      session_id: sessionId,
    };

    return this.createResult(finalContext, Date.now() - startTime);
  }

  /**
   * Create a protected context that prevents blocked property from being unset once locked
   */
  private createContext(context: ChainmailContext): ChainmailContext {
    return new Proxy(context, {
      set(target, prop, value) {
        if (prop === "blocked" && target.blocked && value === false) {
          throw new Error(
            "Cannot unblock: blocked property is locked once set to true"
          );
        }

        if (["input", "start_time", "session_id"].includes(prop as string)) {
          throw new Error(`Property '${String(prop)}' is readonly`);
        }

        Reflect.set(target, prop, value);

        return true;
      },
    });
  }

  /**
   * Create a secure result that derives success from blocked state
   */
  private createResult(
    context: ChainmailContext,
    processingTime: number,
    error?: string
  ): ChainmailResult {
    const result = {
      context: Object.freeze({ ...context }),
      processing_time: processingTime,
      ...(error && { error }),
    };

    return new Proxy(result as ChainmailResult, {
      get(target, prop) {
        if (prop === "success") {
          return !(target as ChainmailResult).context.blocked;
        }
        return Reflect.get(target, prop);
      },
      set(target, prop, value) {
        if (prop === "success") {
          throw new Error("Cannot modify success: derived from blocked state");
        }
        if (prop === "context") {
          throw new Error("Cannot modify context: immutable after creation");
        }

        Reflect.set(target, prop, value);

        return true;
      },
      defineProperty() {
        throw new Error("Cannot define properties on secure result");
      },
      deleteProperty() {
        throw new Error("Cannot delete properties from secure result");
      },
    });
  }

  /**
   * Create a new chainmail with the same rivets
   */
  clone(): PromptChainmail {
    const chainmail = new PromptChainmail();
    chainmail.rivets = new Set(this.rivets);
    return chainmail;
  }

  /**
   * Get the number of rivets in the chainmail
   */
  get length(): number {
    return this.rivets.size;
  }
}
