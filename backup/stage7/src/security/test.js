import { SecurityVerification } from './verification.js';

const hostname = process.argv[2];
const port = Number(process.argv[3] || 443);

if (!hostname) {
  console.error(
    'Usage: node src/security/test.js hostname [port]'
  );
  process.exit(1);
}

const verifier = new SecurityVerification();

console.log('\n================================');
console.log("Let's DANE — Security Verification");
console.log('================================\n');

console.log(`Hostname: ${hostname}`);
console.log(`Port: ${port}`);
console.log(`Resolver: ${verifier.resolver.primary}\n`);

const result = await verifier.verify(hostname, port);

console.log(JSON.stringify(result, null, 2));

console.log('\n================================');

if (result.spki === 'MATCH') {
  console.log('Certificate matches authenticated TLSA.');
} else {
  console.log('VERIFICATION FAILED OR INCOMPLETE.');
}

console.log('Interception:', result.interception);
console.log('================================\n');

if (result.spki !== 'MATCH') {
  process.exitCode = 1;
}
