import { describe, it, expect } from "vitest";
import {
  CombinedClassifier,
  getCombinedClassifier,
  setCombinedClassifierForTests,
} from "./@shared/classifier";
import { resetClassifierStateForTests } from "./test-setup";

describe("resetClassifierStateForTests", () => {
  it("clears an injected fake combined classifier back to a fresh default instance", () => {
    const fake = {} as CombinedClassifier;
    setCombinedClassifierForTests(fake);
    expect(getCombinedClassifier()).toBe(fake);

    resetClassifierStateForTests();

    expect(getCombinedClassifier()).not.toBe(fake);
    expect(getCombinedClassifier()).toBeInstanceOf(CombinedClassifier);
  });
});

describe("global classifier singleton isolation across tests (setupFiles beforeEach/afterEach)", () => {
  it("leaks a fake combined classifier without manual cleanup (part 1)", () => {
    const fake = {} as CombinedClassifier;
    setCombinedClassifierForTests(fake);
    expect(getCombinedClassifier()).toBe(fake);
    // Intentionally no manual reset here: the global setupFiles hook must
    // clean this up before the next test runs.
  });

  it("does not see the previous test's injected fake classifier (part 2)", () => {
    expect(getCombinedClassifier()).toBeInstanceOf(CombinedClassifier);
  });
});
