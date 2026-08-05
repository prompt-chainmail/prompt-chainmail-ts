import vectors from "./normalization-vectors.json";
import {
  normalizeClassifierText,
  windowClassifierBytes,
  windowClassifierRanges,
} from "./classifier-normalize";

type Repetition = {
  value: string;
  count: number;
};

type WindowExpectation =
  | { utf8_hex: string }
  | { repeat: { utf8_hex: string; count: number } };

type WindowVector = {
  name: string;
  input?: string;
  input_repeat?: Repetition;
  size: number;
  stride: number;
  windows: WindowExpectation[];
};

function vectorInput(vector: WindowVector): string {
  if (vector.input !== undefined) {
    return vector.input;
  }
  if (vector.input_repeat !== undefined) {
    return vector.input_repeat.value.repeat(vector.input_repeat.count);
  }
  throw new Error(`Window vector "${vector.name}" has no input`);
}

function bytesFromHex(hex: string): Uint8Array {
  return Uint8Array.from(
    hex.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? []
  );
}

function expectedWindow(window: WindowExpectation): Uint8Array {
  if ("utf8_hex" in window) {
    return bytesFromHex(window.utf8_hex);
  }

  const unit = bytesFromHex(window.repeat.utf8_hex);
  return Uint8Array.from(
    Array.from({ length: window.repeat.count }, () => [...unit]).flat()
  );
}

describe("classifier normalization golden vectors", () => {
  it.each(vectors.normalization_vectors)(
    "$name",
    ({ input, normalized, utf8_hex }) => {
      const actual = normalizeClassifierText(input);

      expect(actual).toBe(normalized);
      expect(new TextEncoder().encode(actual)).toEqual(bytesFromHex(utf8_hex));
    }
  );

  it("replaces a lone surrogate with U+FFFD", () => {
    const actual = normalizeClassifierText("A\ud800B");

    expect(actual).toBe("a\ufffdb");
    expect(new TextEncoder().encode(actual)).toEqual(
      bytesFromHex("61efbfbd62")
    );
  });
});

describe("classifier windowing golden vectors", () => {
  it.each(vectors.window_vectors as WindowVector[])("$name", (vector) => {
    const actual = windowClassifierBytes(
      vectorInput(vector),
      vector.size,
      vector.stride
    );

    expect(actual).toEqual(vector.windows.map(expectedWindow));
    for (const window of actual) {
      expect(window.byteLength).toBeLessThanOrEqual(vector.size);
      expect(
        new TextDecoder("utf-8", { fatal: true }).decode(window)
      ).toBeTypeOf("string");
    }
  });

  it.each([
    [0, 1],
    [1, 0],
    [-1, 1],
    [1, -1],
  ])("rejects non-positive size %i and stride %i", (size, stride) => {
    expect(() => windowClassifierBytes("text", size, stride)).toThrow(
      RangeError
    );
  });
});

describe("classifier windowing byte ranges (start/end offsets)", () => {
  it("reports [0, length] for a single window below the default size", () => {
    const text = "A".repeat(900);
    const normalizedLength = new TextEncoder().encode(
      normalizeClassifierText(text)
    ).length;

    const ranges = windowClassifierRanges(text);

    expect(ranges.map((r) => [r.start, r.end])).toEqual([
      [0, normalizedLength],
    ]);
  });

  it("reports real, non-cumulative start/end offsets for overlapping default (1024/768) windows, clamped at the end", () => {
    const text = "A".repeat(1800);
    const normalizedLength = new TextEncoder().encode(
      normalizeClassifierText(text)
    ).length;

    const ranges = windowClassifierRanges(text);

    expect(ranges.map((r) => [r.start, r.end])).toEqual([
      [0, 1024],
      [768, 1792],
      [1536, normalizedLength],
    ]);
    for (const range of ranges) {
      expect(range.end).toBeLessThanOrEqual(normalizedLength);
      expect(range.bytes).toEqual(
        new TextEncoder()
          .encode(normalizeClassifierText(text))
          .slice(range.start, range.end)
      );
    }
  });

  it("backtracks start/end to real UTF-8 character boundaries for multibyte text, never splitting a code point", () => {
    // "ab😀cdéfg" (already lower/NFKC-normalized): 😀 is 4 bytes, é is 2
    // bytes, so a naive byte-6/stride-4 window would otherwise land mid
    // code point at nominal offsets 4 and 8.
    const text = "AB😀CDéFG";
    const encoded = new TextEncoder().encode(normalizeClassifierText(text));

    const ranges = windowClassifierRanges(text, 6, 4);

    expect(ranges.map((r) => [r.start, r.end])).toEqual([
      [0, 6],
      [2, 8],
      [8, 12],
    ]);
    expect(encoded.length).toBe(12);
    for (const range of ranges) {
      expect(range.end).toBeLessThanOrEqual(encoded.length);
      expect(range.bytes).toEqual(encoded.slice(range.start, range.end));
      expect(() =>
        new TextDecoder("utf-8", { fatal: true }).decode(range.bytes)
      ).not.toThrow();
    }
  });

  it("windowClassifierBytes stays a pure bytes-only compatibility view over windowClassifierRanges", () => {
    const text = "AB😀CDéFG";

    const ranges = windowClassifierRanges(text, 6, 4);
    const bytesOnly = windowClassifierBytes(text, 6, 4);

    expect(bytesOnly).toEqual(ranges.map((r) => r.bytes));
  });
});
