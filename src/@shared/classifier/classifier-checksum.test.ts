import { describe, it, expect } from "vitest";
import { base64ToBytes, sha256Hex } from "./classifier-checksum";

describe("base64ToBytes", () => {
  it("decodes base64 to the exact original bytes", () => {
    const original = new Uint8Array([0, 1, 2, 253, 254, 255]);
    const base64 = Buffer.from(original).toString("base64");

    expect(base64ToBytes(base64)).toEqual(original);
  });

  it("decodes an empty string to zero bytes", () => {
    expect(base64ToBytes("")).toEqual(new Uint8Array(0));
  });
});

describe("sha256Hex", () => {
  it("matches the known SHA-256 of an empty input", async () => {
    const hash = await sha256Hex(new Uint8Array(0));
    expect(hash).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });

  it("matches the known SHA-256 of 'abc'", async () => {
    const hash = await sha256Hex(new TextEncoder().encode("abc"));
    expect(hash).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  });
});
