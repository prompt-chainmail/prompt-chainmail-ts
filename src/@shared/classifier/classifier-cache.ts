/**
 * Minimal bounded LRU cache. Used to cache inference sessions and per-text
 * classifications so repeated calls (e.g. multiple rivets classifying the
 * same sanitized text) do not re-run inference.
 */
export class BoundedCache<K, V> {
  private readonly maxEntries: number;
  private readonly store = new Map<K, V>();

  constructor(maxEntries: number) {
    if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
      throw new RangeError("maxEntries must be a positive integer");
    }
    this.maxEntries = maxEntries;
  }

  get(key: K): V | undefined {
    if (!this.store.has(key)) {
      return undefined;
    }
    const value = this.store.get(key) as V;
    this.store.delete(key);
    this.store.set(key, value);
    return value;
  }

  set(key: K, value: V): void {
    if (this.store.has(key)) {
      this.store.delete(key);
    } else if (this.store.size >= this.maxEntries) {
      const oldestKey = this.store.keys().next().value as K;
      this.store.delete(oldestKey);
    }
    this.store.set(key, value);
  }

  has(key: K): boolean {
    return this.store.has(key);
  }

  get size(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }
}
