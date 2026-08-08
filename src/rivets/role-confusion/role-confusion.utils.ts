import {
  CombinedClassifier,
  SemanticDetectionResult,
  getCombinedClassifier,
} from "../../@shared/classifier";

export interface ConfusionPatternDetectionResult extends SemanticDetectionResult {}

export class RoleConfusionDetector {
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
  ): Promise<ConfusionPatternDetectionResult> {
    return this.classifier.classifyFamily(
      text,
      languageCode,
      "role_confusion",
      {
        confidenceThreshold: this.confidenceThreshold,
      }
    );
  }
}
