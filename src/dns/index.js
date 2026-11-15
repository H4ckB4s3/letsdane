
import { DnsResolver } from './resolver.js';
import { DnssecValidator } from './dnssec.js';

export function createDnsSecurity(options = {}) {
  const resolver = new DnsResolver(options);
  const validator = new DnssecValidator(resolver);

  return {
    resolver,
    validator,

    async resolveAndValidateTLSA(domain, port = 443, proto = 'tcp') {
      return validator.verifyTLSA(domain, port, proto);
    }
  };
}
