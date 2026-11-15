import dns from 'node:dns';

// createProxyLookup returns a function bound to a MUTABLE TLD set,
// so dashboard edits to the ICANN TLD list take effect immediately
// without restarting the proxy.
export function createProxyLookup(resolver, initialTlds) {
  const osLookup = dns.lookup.bind(dns);
  const state = {
    icann: new Set((initialTlds || []).map(t => t.toLowerCase()))
  };

  function lookup(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
    const tld  = host.split('.').pop();
    if (state.icann.has(tld)) return osLookup(hostname, options, callback);

    const wantsV6 = options?.family === 6;
    const type = wantsV6 ? 'AAAA' : 'A';

    resolver.query(hostname, type)
      .then(response => {
        const answer = (response.answers || []).find(r => r.type === type);
        if (!answer) {
          const err = new Error(`No ${type} record for ${hostname}`);
          err.code = 'ENOTFOUND';
          return callback(err);
        }
        callback(null, answer.data, wantsV6 ? 6 : 4);
      })
      .catch(callback);
  }

  lookup.setIcannTlds = tlds => {
    state.icann = new Set((tlds || []).map(t => t.toLowerCase()));
  };

  return lookup;
}
