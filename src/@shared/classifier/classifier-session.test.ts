import { describe, it, expect, beforeEach, vi } from "vitest";
import type { OrtSessionLike, SessionFactory } from "./classifier.types";

function fakeFactory(): SessionFactory & { createSessionCalls: number } {
  const factory = {
    createSessionCalls: 0,
    async createSession(): Promise<OrtSessionLike> {
      factory.createSessionCalls += 1;
      return {
        async run() {
          return {};
        },
      };
    },
    createInt64Tensor(data: BigInt64Array, dims: readonly number[]) {
      return { data, dims };
    },
  };
  return factory;
}

describe("getClassifierSession", () => {
  beforeEach(async () => {
    vi.resetModules();
  });

  it("caches the session so a second call reuses the first session", async () => {
    const { getClassifierSession, resetClassifierSessionForTests } =
      await import("./classifier-session");
    resetClassifierSessionForTests();
    const factory = fakeFactory();

    const first = await getClassifierSession(factory);
    const second = await getClassifierSession(factory);

    expect(factory.createSessionCalls).toBe(1);
    expect(second.session).toBe(first.session);
  });

  it("returns the validated manifest alongside the session", async () => {
    const { getClassifierSession, resetClassifierSessionForTests } =
      await import("./classifier-session");
    resetClassifierSessionForTests();
    const factory = fakeFactory();

    const { manifest } = await getClassifierSession(factory);

    expect(manifest.schema_version).toBe(1);
    expect(manifest.release_quality).toBe(false);
  });

  it("rejects with a redacted ClassifierError when the embedded checksum does not match the manifest", async () => {
    vi.doMock("./classifier-model-data.generated", () => ({
      CLASSIFIER_MODEL_BASE64: Buffer.from("not the real model bytes").toString(
        "base64"
      ),
      CLASSIFIER_MODEL_SHA256: "0".repeat(64),
      CLASSIFIER_MODEL_BYTE_LENGTH: 25,
    }));

    const {
      getClassifierSession,
      resetClassifierSessionForTests,
      ClassifierError,
    } = await import("./classifier-session");
    resetClassifierSessionForTests();
    const factory = fakeFactory();

    await expect(getClassifierSession(factory)).rejects.toBeInstanceOf(
      ClassifierError
    );
    await expect(getClassifierSession(factory)).rejects.toMatchObject({
      code: expect.stringMatching(/mismatch/),
    });

    vi.doUnmock("./classifier-model-data.generated");
  });

  it("does not include the model bytes or any prompt content in the error message", async () => {
    vi.doMock("./classifier-model-data.generated", () => ({
      CLASSIFIER_MODEL_BASE64: Buffer.from("corrupted").toString("base64"),
      CLASSIFIER_MODEL_SHA256: "1".repeat(64),
      CLASSIFIER_MODEL_BYTE_LENGTH: 9,
    }));

    const { getClassifierSession, resetClassifierSessionForTests } =
      await import("./classifier-session");
    resetClassifierSessionForTests();

    try {
      await getClassifierSession(fakeFactory());
      throw new Error("expected getClassifierSession to reject");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      expect(message).not.toContain("corrupted");
      expect(message.length).toBeLessThan(200);
    }

    vi.doUnmock("./classifier-model-data.generated");
  });

  it("only clears the cache after a failure when the test-only reset hook is called (no automatic retry)", async () => {
    vi.doMock("./classifier-model-data.generated", () => ({
      CLASSIFIER_MODEL_BASE64: Buffer.from("bad").toString("base64"),
      CLASSIFIER_MODEL_SHA256: "2".repeat(64),
      CLASSIFIER_MODEL_BYTE_LENGTH: 3,
    }));

    const { getClassifierSession, resetClassifierSessionForTests } =
      await import("./classifier-session");
    resetClassifierSessionForTests();

    await expect(getClassifierSession(fakeFactory())).rejects.toThrow();
    vi.doUnmock("./classifier-model-data.generated");
    vi.resetModules();

    const fresh = await import("./classifier-session");
    fresh.resetClassifierSessionForTests();
    const factory = fakeFactory();
    await expect(fresh.getClassifierSession(factory)).resolves.toBeDefined();
  });

  it("keeps the rejected session promise cached so createSession is not retried per request", async () => {
    const { getClassifierSession, resetClassifierSessionForTests } =
      await import("./classifier-session");
    resetClassifierSessionForTests();

    let createSessionCalls = 0;
    const failingFactory: SessionFactory = {
      async createSession(): Promise<OrtSessionLike> {
        createSessionCalls += 1;
        throw new Error("simulated session-creation failure");
      },
      createInt64Tensor(data: BigInt64Array, dims: readonly number[]) {
        return { data, dims };
      },
    };

    const first = getClassifierSession(failingFactory).catch((error) => error);
    const second = getClassifierSession(failingFactory).catch((error) => error);
    const [firstError, secondError] = await Promise.all([first, second]);

    expect(createSessionCalls).toBe(1);
    expect(firstError.code).toBe("session_create_failed");
    expect(secondError.code).toBe("session_create_failed");

    // A third call after the first two have settled, without an explicit
    // test-only reset, must observe the same cached rejection rather than
    // re-running checksum verification and session creation.
    const third = await getClassifierSession(failingFactory).catch(
      (error) => error
    );
    expect(createSessionCalls).toBe(1);
    expect(third.code).toBe("session_create_failed");

    // The reset hook is the only sanctioned way to force a retry (e.g. after
    // a deliberate process restart in a long-lived server, or in tests).
    resetClassifierSessionForTests();
    const workingFactory = fakeFactory();
    await expect(getClassifierSession(workingFactory)).resolves.toBeDefined();
    expect(workingFactory.createSessionCalls).toBe(1);
  });
});
