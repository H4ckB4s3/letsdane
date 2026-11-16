// Replace Node's dns.lookup with a split resolver:
//   - ICANN TLDs -> OS resolver
//   - everything else -> HNS resolver
//
// Needed because http-mitm-proxy@1.1.0 calls net.connect() without a
// lookup option, so it goes through dns.lookup() (OS-only).
//
// Call ONCE at startup, BEFORE http-mitm-proxy runs.
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';

export function patchSystemDns(resolver, icannTlds) {
  const originalLookup = dns.lookup.bind(dns);
  const originalPromiseLookup = dnsPromises.lookup.bind(dnsPromises);
  const icannSet = new Set((icannTlds || []).map(t => String(t).toLowerCase()));

  function shouldUseHns(hostname) {
    const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
    if (!host || host === 'localhost') return false;
    if (/^[0-9.]+$/.test(host)) return false;
    if (host.includes(':')) return false;
    const tld = host.split('.').pop();
    return !icannSet.has(tld);
  }

  function doHnsLookup(hostname, options) {
    const wantsV6 = options && options.family === 6;
    const type = wantsV6 ? 'AAAA' : 'A';
    return resolver.query(hostname, type).then(res => {
      const answer = (res.answers || []).find(r => r.type === type);
      if (!answer) {
        const err = new Error('getaddrinfo ENOTFOUND ' + hostname);
        err.code = 'ENOTFOUND';
        err.errno = -3008;
        err.syscall = 'getaddrinfo';
        err.hostname = hostname;
        throw err;
      }
      const family = wantsV6 ? 6 : 4;
      if (options && options.all) return [{ address: answer.data, family: family }];
      return { address: answer.data, family: family };
    });
  }

  dns.lookup = function patchedLookup(hostname, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    }
    options = options || {};

    if (!shouldUseHns(hostname)) {
      return originalLookup(hostname, options, callback);
    }

    doHnsLookup(hostname, options).then(
      result => {
        if (options.all) callback(null, result);
        else callback(null, result.address, result.family);
      },
      err => callback(err)
    );
  };

  dnsPromises.lookup = async function patchedPromiseLookup(hostname, options) {
    options = options || {};
    if (!shouldUseHns(hostname)) {
      return originalPromiseLookup(hostname, options);
    }
    return doHnsLookup(hostname, options);
  };

  return () => {
    dns.lookup = originalLookup;
    dnsPromises.lookup = originalPromiseLookup;
  };
}
