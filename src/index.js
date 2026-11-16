#!/usr/bin/env node

import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { LocalCA } from './certificates/ca.js';
import { ensureMitmCa } from './certificates/bootstrap-ca.js';
import { createDashboard } from './dashboard/server.js';
import { DaneProxy } from './proxy/http-proxy.js';
import { DnsResolver } from './dns/resolver.js';
import { SettingsStore } from './config/settings.js';
import { SecurityVerification } from './security/verification.js';
import { createProxyLookup } from './security/proxy-lookup.js';
import { patchSystemDns } from './security/patch-system-dns.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  console.log("Let's DANE JS — Security manager");

  const settingsStore = new SettingsStore(path.join(__dirname, '../data/settings.json'));
  const settings = settingsStore.get();

  const resolver = new DnsResolver({
    activeResolver: settings.activeResolver,
    secondary: settings.secondary,
    useSecondary: settings.useSecondary,
    timeout: settings.timeout,
    useLocalNode: settings.useLocalNode,
    localNodeAddress: settings.localNodeAddress,
    localNodePort: settings.localNodePort
  });

  console.log('\nDNS configuration');
  console.log('HNS resolver:', settings.activeResolver);
  if (settings.useLocalNode) {
    console.log('Local node:', `${settings.localNodeAddress}:${settings.localNodePort}`);
  }

  // Shadow dns.lookup globally: HNS names go to the HNS resolver,
  // ICANN names go to the OS resolver. This is what makes http-mitm-proxy
  // find HNS names for plain HTTP and for CONNECT targets.
  patchSystemDns(resolver, settings.icannTlds || []);
  console.log('[DNS] system resolver patched for HNS names');

  const securityVerifier = new SecurityVerification({
    resolver,
    icannTlds: settings.icannTlds || []
  });

  const proxyLookup = createProxyLookup(resolver, settings.icannTlds || []);

  console.log('\nSecurity verification initialized');

  const caDir = path.join(__dirname, '../data', 'ca');
  const bootstrapped = ensureMitmCa(caDir);
  console.log(bootstrapped.created
    ? '✓ Generated fresh CA (Non Slave Root CA)'
    : '✓ Loaded existing CA');

  const ca = new LocalCA(caDir);
  await ca.ensure();

  console.log('\nProxy CA initialized');
  console.log('CA fingerprint:', ca.getFingerprint());

  const proxy = new DaneProxy(ca, {
    port: 8080,
    resolver,
    securityVerifier,
    proxyLookup
  });

  await proxy.start();

  const dashboard = createDashboard(ca, {
    port: 3000,
    proxyStatus: 'active',
    proxyAddress: '127.0.0.1:8080',
    settingsStore,
    resolver,
    securityVerifier,
    proxyLookup
  });

  console.log('\n================================');
  console.log("Let's DANE started");
  console.log('Dashboard: http://127.0.0.1:3000');
  console.log('Proxy:     http://127.0.0.1:8080');
  console.log('================================');

  return { dashboard, proxy };
}

main().catch(error => {
  console.error('Startup failed:', error);
  process.exit(1);
});
