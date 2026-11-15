#!/usr/bin/env node

import dns from 'node:dns';

import { LocalCA } from './certificates/ca.js';
import { createDashboard } from './dashboard/server.js';
import { DaneProxy } from './proxy/http-proxy.js';

import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Configure Node.js DNS to use your HNS resolvers.
const HNS_DNS_SERVERS = [
  '82.68.70.162',
  '82.68.70.163'
];

// Apply DNS configuration before starting the application.
dns.setServers(HNS_DNS_SERVERS);

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  console.log("Let's DANE JS — Local DANE security manager");

  console.log('\nConfiguring HNS DNS resolvers…');

  console.log('✓ Primary DNS:', HNS_DNS_SERVERS[0]);
  console.log('✓ Secondary DNS:', HNS_DNS_SERVERS[1]);

  console.log('\nInitializing local Certificate Authority…');

  const dataDir = path.join(__dirname, '../data/ca');
  const ca = new LocalCA(dataDir);

  const result = await ca.ensure();

  if (result.created) {
    console.log('✓ Generated new local CA (private key stored locally only)');
  } else {
    console.log('✓ Loaded existing local CA');
  }

  const info = ca.getInfo();

  console.log(`  Subject: ${info.subject}`);
  console.log(`  Fingerprint: ${info.fingerprint}`);
  console.log(`  Valid until: ${info.notAfter.toISOString().split('T')[0]}`);

  console.log('\nTesting HNS DNS resolution…');

  try {
    const addresses = await dns.promises.resolve4('syndicate');

    console.log('✓ HNS DNS resolution successful');

    for (const address of addresses) {
      console.log(`  IPv4: ${address}`);
    }
  } catch (err) {
    console.warn('⚠ HNS DNS resolution failed:', err.message);
    console.warn('Check your HNS DNS servers before testing the proxy.');
  }

  console.log('\nStarting DANE proxy…');

  const proxy = new DaneProxy(ca, {
    port: 8080
  });

  await proxy.start().catch(err => {
    console.error('Proxy startup failed:', err.message);
    throw err;
  });

  console.log('\nStarting dashboard…');

  const dashboard = createDashboard(ca, {
    port: 3000,
    proxyStatus: 'active',
    proxyAddress: '127.0.0.1:8080'
  });

  console.log('\n────────────────────────────────────────');
  console.log('Dashboard:  http://127.0.0.1:3000');
  console.log('Proxy:      http://127.0.0.1:8080');
  console.log('CA cert:    http://127.0.0.1:3000/api/ca/cert.pem');
  console.log('────────────────────────────────────────');

  console.log('\nPrimary target: Firefox');

  console.log('1. Download the root CA from the dashboard');
  console.log('2. Import it into Firefox Authorities');
  console.log('3. Trust it for identifying websites');
  console.log('4. Configure Firefox proxy: 127.0.0.1:8080');

  console.log('\nDNS configuration:');
  console.log('Primary:', HNS_DNS_SERVERS[0]);
  console.log('Secondary:', HNS_DNS_SERVERS[1]);

  console.log('\nIMPORTANT:');
  console.log('DNS resolution is configured for HNS.');
  console.log('DNSSEC cryptographic validation must still be implemented.');
  console.log('TLSA authentication must be verified before claiming DANE security.');
}

main().catch(err => {
  console.error('\nFailed to start:', err);
  process.exit(1);
});
