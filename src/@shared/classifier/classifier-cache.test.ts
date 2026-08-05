import { describe, it, expect } from "vitest";
import { BoundedCache } from "./classifier-cache";

describe("BoundedCache", () => {
  it("returns undefined for missing keys", () => {
    const cache = new BoundedCache<string, number>(2);
    expect(cache.get("missing")).toBeUndefined();
  });

  it("stores and retrieves values", () => {
    const cache = new BoundedCache<string, number>(2);
    cache.set("a", 1);
    expect(cache.get("a")).toBe(1);
    expect(cache.size).toBe(1);
  });

  it("evicts the least recently used entry once capacity is exceeded", () => {
    const cache = new BoundedCache<string, number>(2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);

    expect(cache.has("a")).toBe(false);
    expect(cache.get("b")).toBe(2);
    expect(cache.get("c")).toBe(3);
    expect(cache.size).toBe(2);
  });

  it("refreshes recency on get", () => {
    const cache = new BoundedCache<string, number>(2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.get("a");
    cache.set("c", 3);

    expect(cache.has("a")).toBe(true);
    expect(cache.has("b")).toBe(false);
  });

  it("rejects a non-positive maxEntries", () => {
    expect(() => new BoundedCache(0)).toThrow(RangeError);
    expect(() => new BoundedCache(-1)).toThrow(RangeError);
  });

  it("clears all entries", () => {
    const cache = new BoundedCache<string, number>(2);
    cache.set("a", 1);
    cache.clear();
    expect(cache.size).toBe(0);
  });
});
