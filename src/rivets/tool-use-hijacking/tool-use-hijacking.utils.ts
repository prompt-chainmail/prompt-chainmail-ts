import {
  CombinedClassifier,
  SemanticDetectionResult,
  getCombinedClassifier,
} from "../../@shared/classifier";

export class ToolHijackDetector {
  private readonly classifier: CombinedClassifier;
  private readonly confidenceThreshold?: number;

  constructor(
    configOverrides: { confidenceThreshold?: number } = {},
    classifier: CombinedClassifier = getCombinedClassifier()
  ) {
    this.classifier = classifier;
    this.confidenceThreshold = configOverrides.confidenceThreshold;
  }

  public async detect(
    text: string,
    languageCode: string
  ): Promise<SemanticDetectionResult> {
    return this.classifier.classifyFamily(
      text,
      languageCode,
      "tool_use_hijacking",
      {
        confidenceThreshold: this.confidenceThreshold,
      }
    );
  }
}
