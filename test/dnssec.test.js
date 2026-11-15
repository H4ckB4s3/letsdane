
import { createDnsSecurity } from '../src/dns/index.js';

const { resolver, validator } = createDnsSecurity();

async function main() {
  console.log('\n--- LetsDANE DNSSEC Test ---\n');

  // Test 1: Basic DNS connectivity
  console.log('[1] Testing DNS-over-HTTPS');

  const response = await resolver.query('cloudflare.com', 'A');

  console.log('Response:', response.answers);

  // Test 2: DNSSEC validation
  console.log('\n[2] Testing DNSSEC validation');

  const result = await validator.validate(
    'cloudflare.com',
    'A'
  );

  console.log('Status:', result.status);
  console.log('Valid:', result.valid);
  console.log('Reason:', result.reason);

  // Test 3: TLSA validation
  console.log('\n[3] Testing TLSA validation');

  const tlsa = await validator.verifyTLSA(
    'cloudflare.com',
    443,
    'tcp'
  );

  console.log('Status:', tlsa.status);
  console.log('Valid:', tlsa.valid);
  console.log('Records:', tlsa.records);
  console.log('Reason:', tlsa.reason);

  console.log('\n--- Tests completed ---');
}

main().catch(error => {
  console.error('Test failed:', error);
  process.exitCode = 1;
});
