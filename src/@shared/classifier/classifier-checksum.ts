/**
 * Cross-runtime helpers for decoding the embedded base64 model and verifying
 * its checksum, without assuming Node's Buffer is globally available
 * (bundled output may run in a browser).
 */

export function base64ToBytes(base64: string): Uint8Array {
  if (typeof globalThis.Buffer !== "undefined") {
    return new Uint8Array(globalThis.Buffer.from(base64, "base64"));
  }

  const binary = globalThis.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle) {
    const digest = await subtle.digest("SHA-256", bytes as BufferSource);
    return bytesToHex(new Uint8Array(digest));
  }

  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(bytes).digest("hex");
}
