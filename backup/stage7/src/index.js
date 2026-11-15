#!/usr/bin/env node

import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { LocalCA } from './certificates/ca.js';
import { createDashboard } from './dashboard/server.js';
import { DaneProxy } from './proxy/http-proxy.js';
import { DnsResolver } from './dns/resolver.js';
import { SettingsStore } from './config/settings.js';
import { SecurityVerification } from './security/verification.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  console.log("Let's DANE JS — Security manager");

  const settingsStore = new SettingsStore(
    path.join(__dirname, '../data/settings.json')
  );

  const settings = settingsStore.get();

  const resolver = new DnsResolver({
    ...settings,
    useSecondary: false
  });

  // IMPORTANT: Do NOT call dns.setServers() with only the HNS resolver.
  // Doing so breaks Node's internal getaddrinfo for normal hostnames
  // (hnsbroker, google.com, upstream TLS connections, etc.).
  // We leave the OS resolver in place and rely on DnsResolver for DANE lookups.

  console.log('\nDNS configuration');
  console.log('HNS resolver:', settings.primary);
  console.log('Trust mode:', settings.trustMode);

  const securityVerifier = new SecurityVerification({
    resolver,
    icannDomains: settings.icannDomains
  });

  console.log('\nSecurity verification initialized');

  const ca = new LocalCA(
    path.join(__dirname, '../data/ca')
  );

  await ca.ensure();

  const proxy = new DaneProxy(ca, {
    port: 8080,
    resolver,
    securityVerifier
  });

  await proxy.start();

  console.log('\nProxy CA initialized');
  console.log('CA fingerprint:', ca.getFingerprint());

  const dashboard = createDashboard(ca, {
    port: 3000,
    proxyStatus: 'active',
    proxyAddress: '127.0.0.1:8080',
    settingsStore,
    resolver,
    securityVerifier
  });

  console.log('\n================================');
  console.log("Let's DANE started");
  console.log('Dashboard: http://127.0.0.1:3000');
  console.log('Proxy:     http://127.0.0.1:8080');
  console.log('Trust:     ' + settings.trustMode);
  console.log('================================');

  return { dashboard, proxy };
}

main().catch(error => {
  console.error('Startup failed:', error);
  process.exit(1);
});
