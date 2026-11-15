import { DnsResolver } from './src/dns/resolver.js';

const resolver = new DnsResolver({
  primary: '82.68.70.162',
  useSecondary: false,
  timeout: 8000
});

for (const hostname of ['syndicate', 'merino.services.mozilla.com']) {
  console.log('\n========== HOST:', hostname, '==========');

  try {
    const response = await resolver.query(
      `_443._tcp.${hostname}`,
      'TLSA'
    );

    console.dir({
      rcode: response.rcode,
      answers: response.answers,
      authorities: response.authorities
    }, { depth: 8 });

  } catch (error) {
    console.error('ERROR:', error.message);
  }
}
