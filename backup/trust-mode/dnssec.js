import {
  dnssecLookUp,
  Question,
  SecurityStatus
} from '@relaycorp/dnssec';

export class DnssecValidator {
  constructor(resolver, options = {}) {
    if (!resolver || typeof resolver.queryWire !== 'function') {
      throw new Error('DnssecValidator requires a DnsResolver');
    }

    this.resolver = resolver;
    this.trustMode =
      options.trustMode ||
      process.env.LETSDANE_TRUST_MODE ||
      'configured-resolver';

    if (!['configured-resolver', 'iana-dnssec'].includes(this.trustMode)) {
      throw new Error(`Unsupported trust mode: ${this.trustMode}`);
    }
  }

  async validate(name, type = 'A') {
    try {
      const question = new Question(
        name.endsWith('.') ? name : `${name}.`,
        type.toUpperCase()
      );

      const result = await dnssecLookUp(
        question,
        async q => this.resolver.queryWire(
          q.name,
          q.getTypeName()
        )
      );

      const secure = result.status === SecurityStatus.SECURE;

      return {
        valid: secure,
        status: secure ? 'secure' : String(result.status).toLowerCase(),
        reason: secure
          ? 'DNSSEC cryptographic chain verified'
          : (result.reasonChain || []).join('; ') ||
            'DNSSEC validation failed',
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

    try {
      if (this.trustMode === 'configured-resolver') {
        const response = await this.resolver.query(name, 'TLSA');

        if (response.rcode !== 'NOERROR') {
          return {
            valid: false,
            status: response.rcode.toLowerCase(),
            reason: `TLSA query failed: ${response.rcode}`,
            records: [],
            ttlSeconds: null
          };
        }

        const records = (response.answers || []).filter(
          record => record.type === 'TLSA'
        );

        if (!records.length) {
          return {
            valid: false,
            status: 'empty',
            reason: 'Trusted resolver returned no TLSA records',
            records: [],
            ttlSeconds: null
          };
        }

        return {
          valid: true,
          status: 'trusted-resolver',
          reason: `TLSA records supplied by configured resolver ${this.resolver.primary}`,
          records: records.map(record => ({
            ...(record.dataFields || record.data || record),
            ttl: record.ttl
          })),
          ttlSeconds: Math.min(...records.map(r => r.ttl))
        };
      }

      const validation = await this.validate(name, 'TLSA');

      if (!validation.valid) {
        return {
          valid: false,
          status: validation.status,
          reason: validation.reason,
          records: [],
          ttlSeconds: null
        };
      }

      const records = validation.result.records || [];

      if (!records.length) {
        return {
          valid: false,
          status: 'bogus',
          reason: 'No TLSA records returned',
          records: [],
          ttlSeconds: null
        };
      }

      const ttlValues = records
        .map(record => record.ttl)
        .filter(Number.isFinite);

      return {
        valid: true,
        status: 'secure',
        reason: 'TLSA RRset cryptographically validated',
        records: records.map(record =>
          record.dataFields || record
        ),
        ttlSeconds: ttlValues.length
          ? Math.min(...ttlValues)
          : null
      };

    } catch (error) {
      return {
        valid: false,
        status: 'indeterminate',
        reason: error.message,
        records: [],
        ttlSeconds: null
      };
    }
  }
}
