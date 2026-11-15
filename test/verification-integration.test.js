import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { SecurityVerification } from '../src/security/verification.js';
import { VerificationCache } from '../src/security/verification-cache.js';

describe('Verification integration', () => {
  it('uses an isolated verification cache', () => {
    const cache = new VerificationCache();

    const verifier = new SecurityVerification({
      cache,
      trustMode: 'configured-resolver'
    });

    assert.equal(verifier.cache, cache);
    assert.equal(cache.size, 0);
  });

  it('does not cache failed verification', () => {
    const cache = new VerificationCache();

    const verifier = new SecurityVerification({
      cache,
      trustMode: 'configured-resolver'
    });

    const accepted = cache.set(
      'merino.services.mozilla.com',
      443,
      'configured-resolver',
      {
        spki: 'MISMATCH',
        interception: 'BLOCKED'
      },
      192
    );

    assert.equal(accepted, false);
    assert.equal(cache.size, 0);
  });
});
