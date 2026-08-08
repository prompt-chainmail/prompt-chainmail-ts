import { afterEach, beforeEach } from "vitest";
import {
  resetClassifierSessionForTests,
  resetCombinedClassifierForTests,
} from "./@shared/classifier";

/** Resets classifier singletons between tests that inject fakes. */
export function resetClassifierStateForTests(): void {
  resetCombinedClassifierForTests();
  resetClassifierSessionForTests();
}

beforeEach(() => {
  resetClassifierStateForTests();
});

afterEach(() => {
  resetClassifierStateForTests();
});
