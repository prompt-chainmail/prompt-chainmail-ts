import * as ort from "onnxruntime-web";
import { base64ToBytes, sha256Hex } from "./classifier-checksum";
import {
  CLASSIFIER_MODEL_BASE64,
  CLASSIFIER_MODEL_SHA256,
} from "./classifier-model-data.generated";
import { CLASSIFIER_MANIFEST } from "./classifier-manifest";
import {
  ClassifierManifest,
  OrtSessionLike,
  SessionFactory,
} from "./classifier.types";

export class ClassifierError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ClassifierError";
    this.code = code;
  }
}

export const defaultSessionFactory: SessionFactory = {
  async createSession(modelBytes: Uint8Array): Promise<OrtSessionLike> {
    const session = await ort.InferenceSession.create(modelBytes, {
      executionProviders: ["wasm"],
    });
    return session as unknown as OrtSessionLike;
  },
  createInt64Tensor(data: BigInt64Array, dims: readonly number[]): unknown {
    return new ort.Tensor("int64", data, dims as number[]);
  },
};

export interface ClassifierSessionHandle {
  session: OrtSessionLike;
  manifest: ClassifierManifest;
}

let cachedSessionPromise: Promise<ClassifierSessionHandle> | null = null;

async function createClassifierSession(
  factory: SessionFactory
): Promise<ClassifierSessionHandle> {
  const modelBytes = base64ToBytes(CLASSIFIER_MODEL_BASE64);

  if (modelBytes.length !== CLASSIFIER_MANIFEST.model_size_bytes) {
    throw new ClassifierError(
      "model_size_mismatch",
      "Embedded classifier model size does not match the manifest"
    );
  }

  const computedChecksum = await sha256Hex(modelBytes);
  if (
    computedChecksum !== CLASSIFIER_MANIFEST.model_sha256 ||
    computedChecksum !== CLASSIFIER_MODEL_SHA256
  ) {
    throw new ClassifierError(
      "checksum_mismatch",
      "Embedded classifier model checksum does not match the manifest"
    );
  }

  try {
    const session = await factory.createSession(modelBytes);
    return { session, manifest: CLASSIFIER_MANIFEST };
  } catch {
    throw new ClassifierError(
      "session_create_failed",
      "Failed to create classifier inference session"
    );
  }
}

/**
 * Returns a cached, shared classifier session. The first caller pays
 * checksum verification and session-creation cost; subsequent callers reuse
 * the same promise/session.
 */
export function getClassifierSession(
  factory: SessionFactory = defaultSessionFactory
): Promise<ClassifierSessionHandle> {
  if (!cachedSessionPromise) {
    cachedSessionPromise = createClassifierSession(factory);
  }
  return cachedSessionPromise;
}

/** Test-only hook to reset the cached session between test cases. */
export function resetClassifierSessionForTests(): void {
  cachedSessionPromise = null;
}
