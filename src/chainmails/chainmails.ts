import { PromptChainmail, Rivets } from "../index";

/**
 * Pre-forged chainmail configurations
 */
export const Chainmails = {
  /**
   * Basic protection chainmail
   */
  basic(maxLength = 8000, confidenceFilter = 0.6): PromptChainmail {
    return new PromptChainmail()
      .forge(Rivets.sanitize(maxLength))
      .forge(Rivets.patternDetection())
      .forge(Rivets.roleConfusion())
      .forge(Rivets.delimiterConfusion())
      .forge(Rivets.confidenceFilter(confidenceFilter));
  },

  /**
   * Advanced protection chainmail with encoding detection
   */
  advanced(maxLength = 8000, confidenceFilter = 0.6): PromptChainmail {
    return new PromptChainmail()
      .forge(Rivets.sanitize(maxLength))
      .forge(Rivets.patternDetection())
      .forge(Rivets.roleConfusion())
      .forge(Rivets.delimiterConfusion())
      .forge(Rivets.instructionHijacking())
      .forge(Rivets.toolUseHijacking())
      .forge(Rivets.codeInjection())
      .forge(Rivets.sqlInjection())
      .forge(Rivets.templateInjection())
      .forge(Rivets.encodingDetection())
      .forge(Rivets.structureAnalysis())
      .forge(Rivets.confidenceFilter(confidenceFilter))
      .forge(Rivets.rateLimit());
  },

  /**
   * Development chainmail with logging
   */
  development(): PromptChainmail {
    return Chainmails.advanced().forge(Rivets.logger());
  },

  /**
   * Stricter chainmail for high-security environments
   */
  strict(maxLength = 8000, confidenceFilter = 0.8): PromptChainmail {
    return new PromptChainmail()
      .forge(Rivets.sanitize(maxLength))
      .forge(Rivets.patternDetection())
      .forge(Rivets.roleConfusion())
      .forge(Rivets.delimiterConfusion())
      .forge(Rivets.instructionHijacking())
      .forge(Rivets.toolUseHijacking())
      .forge(Rivets.codeInjection())
      .forge(Rivets.sqlInjection())
      .forge(Rivets.templateInjection())
      .forge(Rivets.encodingDetection())
      .forge(Rivets.structureAnalysis())
      .forge(Rivets.confidenceFilter(confidenceFilter))
      .forge(Rivets.rateLimit(50, 60000));
  },
};
