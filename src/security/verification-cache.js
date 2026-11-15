/**
 * Positive-only DANE verification cache.
 *
 * Failed, incomplete or expired results are never accepted.
 */
export class VerificationCache {
  constructor(options = {}) {
    this.maxTtl = options.maxTtl ?? 86400;
    this.entries = new Map();
  }

  getKey(hostname, port, trustMode) {
    return `${hostname.toLowerCase()}:${port}:${trustMode}`;
  }

  get(hostname, port, trustMode) {
    const key = this.getKey(hostname, port, trustMode);
    const entry = this.entries.get(key);

    if (!entry) return null;

    if (Date.now() >= entry.expiresAt) {
      this.entries.delete(key);
      return null;
    }

    return { ...entry.result, cached: true };
  }

  set(hostname, port, trustMode, result, ttlSeconds) {
    if (
      !result ||
      result.spki !== 'MATCH' ||
      result.interception !== 'VERIFICATION_PASSED' ||
      !Number.isFinite(ttlSeconds) ||
      ttlSeconds <= 0
    ) {
      return false;
    }

    const ttl = Math.min(ttlSeconds, this.maxTtl);

    const key = this.getKey(hostname, port, trustMode);

    this.entries.set(key, {
      result: { ...result, cached: false },
      expiresAt: Date.now() + ttl * 1000
    });

    return true;
  }

  delete(hostname, port, trustMode) {
    return this.entries.delete(
      this.getKey(hostname, port, trustMode)
    );
  }

  clear() {
    this.entries.clear();
  }

  get size() {
    return this.entries.size;
  }
}
