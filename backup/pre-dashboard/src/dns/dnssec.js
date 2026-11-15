
import {
  dnssecLookUp,
  Question,
  SecurityStatus
} from '@relaycorp/dnssec';

/**
 * Cryptographic DNSSEC validation.
 *
 * Requires a resolver exposing queryWire(name, type).
 */
export class DnssecValidator {
  constructor(resolver) {
    if (!resolver || typeof resolver.queryWire !== 'function') {
      throw new Error(
        'DnssecValidator requires a DnsResolver instance'
      );
    }

    this.resolver = resolver;
  }

  async validate(name, type = 'A') {
    try {
      const question = new Question(
        name.endsWith('.') ? name : `${name}.`,
        type.toUpperCase()
      );

      const result = await dnssecLookUp(
        question,
        async q => {
          return this.resolver.queryWire(
            q.name,
            q.getTypeName()
          );
        }
      );

      const secure = result.status === SecurityStatus.SECURE;

      return {
        valid: secure,
        status: String(result.status).toLowerCase(),
        reason: secure
          ? 'DNSSEC chain of trust successfully verified'
          : (result.reasonChain || []).join('; ') ||
            'DNSSEC validation did not establish security',
        result: secure ? result.result : null
      };
    } catch (error) {
      return {
        valid: false,
        status: 'indeterminate',
        reason: error.message,
        result: null
      };
    }
  }

  async isSecure(name, type = 'A') {
    const result = await this.validate(name, type);
    return result.valid && result.status === 'secure';
  }

  async verifyTLSA(domain, port = 443, proto = 'tcp') {
    const name = `_${port}._${proto}.${domain}`;

    const validation = await this.validate(name, 'TLSA');

    if (!validation.valid) {
      return {
        valid: false,
        status: validation.status,
        reason: validation.reason,
        records: []
      };
    }

    const records = validation.result.records;

    if (!records || records.length === 0) {
      return {
        valid: false,
        status: 'bogus',
        reason: 'No TLSA records returned',
        records: []
      };
    }

    return {
      valid: true,
      status: 'secure',
      reason: 'TLSA RRset cryptographically validated',
      records: records.map(record => record.dataFields)
    };
  }
}
