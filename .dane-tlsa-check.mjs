import { DnsResolver } from './src/dns/resolver.js';
import { SecurityVerification } from './src/security/verification.js';

const hostname = process.argv[2];

if (!hostname) {
  console.error('Usage: node .dane-tlsa-check.mjs hostname');
  process.exit(1);
}

const resolver = new DnsResolver({
  primary: '82.68.70.162',
  useSecondary: false,
  timeout: 8000
});

const verifier = new SecurityVerification({ resolver });

async function main() {
  console.log('Hostname:', hostname);
  console.log('Resolver:', resolver.primary);
  console.log('Trust mode:', verifier.trustMode);

  const result = await verifier.dnssec.verifyTLSA(
    hostname,
    443,
    'tcp'
  );

  console.log('\n========== TLSA RESULT ==========');
  console.log(JSON.stringify(result, null, 2));

  if (!result.valid || !result.records?.length) {
    throw new Error(
      'No usable TLSA records: ' + result.reason
    );
  }

  console.log('\nPASS: TLSA records retrieved');
}

main().catch(error => {
  console.error('\nFAIL:', error.message);
  process.exitCode = 1;
});
