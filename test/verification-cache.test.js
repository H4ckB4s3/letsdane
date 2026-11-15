import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { VerificationCache } from '../src/security/verification-cache.js';

describe('VerificationCache', () => {
  const success = {
    spki: 'MATCH',
    interception: 'VERIFICATION_PASSED'
  };

  it('stores successful verification', () => {
    const cache = new VerificationCache();

    assert.equal(
      cache.set('syndicate', 443, 'configured-resolver', success, 300),
      true
    );

    assert.equal(cache.size, 1);
  });

  it('rejects mismatched certificates', () => {
    const cache = new VerificationCache();

    assert.equal(
      cache.set('example.com', 443, 'configured-resolver', {
        spki: 'MISMATCH',
        interception: 'BLOCKED'
      }, 300),
      false
    );

    assert.equal(cache.size, 0);
  });

  it('rejects zero and invalid TTL', () => {
    const cache = new VerificationCache();

    assert.equal(
      cache.set('syndicate', 443, 'configured-resolver', success, 0),
      false
    );

    assert.equal(
      cache.set('syndicate', 443, 'configured-resolver', success, NaN),
      false
    );
  });

  it('returns cached successful results', () => {
    const cache = new VerificationCache();

    cache.set('syndicate', 443, 'configured-resolver', success, 300);

    const result = cache.get(
      'syndicate',
      443,
      'configured-resolver'
    );

    assert.equal(result.spki, 'MATCH');
    assert.equal(result.cached, true);
  });

  it('does not share results between trust modes', () => {
    const cache = new VerificationCache();

    cache.set('syndicate', 443, 'configured-resolver', success, 300);

    assert.equal(
      cache.get('syndicate', 443, 'iana-dnssec'),
      null
    );
  });

  it('does not return expired entries', () => {
    const cache = new VerificationCache({ maxTtl: 1 });

    cache.set('syndicate', 443, 'configured-resolver', success, 0.001);

    return new Promise(resolve => {
      setTimeout(() => {
        assert.equal(
          cache.get('syndicate', 443, 'configured-resolver'),
          null
        );

        assert.equal(cache.size, 0);
        resolve();
      }, 20);
    });
  });
});
