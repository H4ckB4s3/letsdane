import { describe, it } from 'node:test';
import assert from 'node:assert';
import { TlsaValidator } from '../src/dns/tlsa.js';

describe('TlsaValidator', () => {
  it('rejects empty TLSA list (fail closed)', () => {
    assert.strictEqual(TlsaValidator.isValid('dummy', []), false);
  });

  it('rejects non-DANE-EE usage', () => {
    const records = [{ data: { usage: 2, selector: 1, matchingType: 1, certificateAssociationData: Buffer.alloc(32) } }];
    assert.strictEqual(TlsaValidator.isValid('dummy', records), false);
  });
});
