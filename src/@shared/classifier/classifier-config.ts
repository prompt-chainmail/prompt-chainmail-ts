import classifierDetectorConfig from "../../@configs/classifier_detector.json" with { type: "json" };
import { ClassifierDetectionConfig } from "./classifier.types";
import { ClassifierFamily } from "./classifier-labels";

/** Loader for the risk-scoring configuration used by each classifier family. */
export class ClassifierConfigLoader {
  static get(family: ClassifierFamily): ClassifierDetectionConfig {
    const config = classifierDetectorConfig.value[family];
    return {
      risk_calculation: config.risk_calculation,
    };
  }
}
