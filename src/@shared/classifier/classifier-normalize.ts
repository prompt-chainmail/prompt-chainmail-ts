const DEFAULT_WINDOW_SIZE = 1024;
const DEFAULT_WINDOW_STRIDE = 768;
const UNICODE_WHITESPACE = new RegExp(
  "[\\u0009-\\u000d\\u0020\\u0085\\u00a0\\u1680" +
    "\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]+",
  "g"
);

export function normalizeClassifierText(text: string): string {
  return replaceLoneSurrogates(text)
    .normalize("NFKC")
    .replace(UNICODE_WHITESPACE, " ")
    .toLowerCase()
    .replace(/^ | $/g, "");
}

/**
 * One windowed slice of the normalized UTF-8 byte stream. `start`/`end` are
 * the real, boundary-adjusted byte offsets into the *full* normalized byte
 * array (never the naive `index * stride`, nor a cumulative sum of prior
 * window lengths), so callers can report exact match offsets even when
 * windows overlap (`stride < size`) or a boundary was backtracked away from
 * a UTF-8 continuation byte.
 */
export interface ClassifierWindow {
  bytes: Uint8Array;
  start: number;
  end: number;
}

export function windowClassifierRanges(
  text: string,
  size = DEFAULT_WINDOW_SIZE,
  stride = DEFAULT_WINDOW_STRIDE
): ClassifierWindow[] {
  if (
    !Number.isInteger(size) ||
    !Number.isInteger(stride) ||
    size <= 0 ||
    stride <= 0
  ) {
    throw new RangeError("size and stride must be positive integers");
  }

  const encoded = new TextEncoder().encode(normalizeClassifierText(text));
  const windows: ClassifierWindow[] = [];
  let previousStart = -1;

  for (
    let nominalStart = 0;
    nominalStart < encoded.length;
    nominalStart += stride
  ) {
    let start = nominalStart;
    while (start > 0 && isContinuationByte(encoded[start])) {
      start -= 1;
    }

    if (start === previousStart) {
      continue;
    }

    let end = Math.min(start + size, encoded.length);
    while (
      end < encoded.length &&
      end > start &&
      isContinuationByte(encoded[end])
    ) {
      end -= 1;
    }

    if (end === start) {
      throw new RangeError("size is too small for a UTF-8 code point");
    }

    windows.push({ bytes: encoded.slice(start, end), start, end });
    previousStart = start;

    if (end === encoded.length) {
      break;
    }
  }

  return windows;
}

/**
 * Compatibility view over {@link windowClassifierRanges} for callers that
 * only need window contents, not byte offsets.
 */
export function windowClassifierBytes(
  text: string,
  size = DEFAULT_WINDOW_SIZE,
  stride = DEFAULT_WINDOW_STRIDE
): Uint8Array[] {
  return windowClassifierRanges(text, size, stride).map(
    (window) => window.bytes
  );
}

function isContinuationByte(value: number): boolean {
  return (value & 0b1100_0000) === 0b1000_0000;
}

function replaceLoneSurrogates(text: string): string {
  return Array.from(text, (character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && codePoint >= 0xd800 && codePoint <= 0xdfff
      ? "\ufffd"
      : character;
  }).join("");
}
