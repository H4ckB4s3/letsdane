import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DnsResolver } from '../dns/resolver.js';
import { isIP } from 'node:net';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function createDashboard(ca, options = {}) {
  const app = express();
  const port = options.port || 3000;
  const publicDir = path.join(__dirname, '../../public');

  app.use(express.json({ limit: '64kb' }));
  app.use(express.static(publicDir));

  const settingsStore = options.settingsStore;
  const resolver = options.resolver;
  const securityVerifier = options.securityVerifier;
  const proxyLookup = options.proxyLookup;

  let latestSecurityResult = null;
  let verificationRunning = false;

  app.get('/api/status', (req, res) => {
    const info = ca.getInfo();
    res.json({
      proxy: {
        status: options.proxyStatus || 'stopped',
        address: options.proxyAddress || '127.0.0.1:8080'
      },
      dnssec: { enabled: true, status: 'namespace_allowlist' },
      tlsa: { enabled: true, status: latestSecurityResult?.tlsa || 'not_tested' },
      ca: { ready: !!info, ...info },
      resolver: {
        primary: resolver?.primary || null,
        active: resolver?.activeServer || null,
        useLocalNode: resolver?.useLocalNode || false,
        localNode: resolver?.useLocalNode
          ? (resolver.localNodeAddress + ":" + resolver.localNodePort)
          : null
      },
      security: latestSecurityResult
    });
  });

  app.get('/api/security/status', (req, res) => {
    res.json({ running: verificationRunning, result: latestSecurityResult });
  });

  app.post('/api/security/verify', async (req, res) => {
    if (!securityVerifier) {
      return res.status(503).json({ ok: false, error: 'Security verifier unavailable' });
    }
    if (verificationRunning) {
      return res.status(409).json({ ok: false, error: 'Verification already running' });
    }

    const hostname = String(req.body.hostname || '').trim();

    if (
      !hostname ||
      hostname.length > 253 ||
      !/^[a-zA-Z0-9.-]+$/.test(hostname) ||
      hostname.startsWith('.') ||
      hostname.endsWith('..')
    ) {
      return res.status(400).json({ ok: false, error: 'Invalid hostname' });
    }

    verificationRunning = true;
    try {
      latestSecurityResult = await securityVerifier.verify(hostname);
      res.json({
        ok:
          latestSecurityResult.spki === 'MATCH' &&
          latestSecurityResult.interception === 'VERIFICATION_PASSED',
        result: latestSecurityResult
      });
    } catch (error) {
      res.status(500).json({ ok: false, error: error.message });
    } finally {
      verificationRunning = false;
    }
  });

  app.get('/api/settings', (req, res) => {
    res.json(settingsStore.get());
  });

  app.put('/api/settings', (req, res) => {
    try {
      if (verificationRunning) {
        return res.status(409).json({
          ok: false,
          error: 'Wait for verification to finish before changing settings'
        });
      }

      const saved = settingsStore.save(req.body);

      resolver.primary = saved.activeResolver;
      resolver.secondary = saved.secondary;
      resolver.useSecondary = saved.useSecondary;
      resolver.timeout = saved.timeout;
      resolver.useLocalNode = saved.useLocalNode;
      resolver.localNodeAddress = saved.localNodeAddress;
      resolver.localNodePort = saved.localNodePort;

      if (securityVerifier && typeof securityVerifier.setIcannTlds === 'function') {
        securityVerifier.setIcannTlds(saved.icannTlds);
      proxyLookup?.setIcannTlds?.(saved.icannTlds);
      } else if (securityVerifier && typeof securityVerifier.setIcannDomains === 'function') {
        securityVerifier.setIcannDomains(saved.icannTlds);
      proxyLookup?.setIcannTlds?.(saved.icannTlds);
      }

      latestSecurityResult = null;

      res.json({
        ok: true,
        settings: saved,
        message: 'Resolver and ICANN TLD policy updated'
      });
    } catch (error) {
      res.status(400).json({ ok: false, error: error.message });
    }
  });

  app.post('/api/resolvers/test', async (req, res) => {
    const server = String(req.body.server || '').trim();
    const version = isIP(server);

    if (version !== 4 && version !== 6) {
      return res.status(400).json({ ok: false, error: 'Invalid IPv4/IPv6 address' });
    }

    try {
      const testResolver = new DnsResolver({
        primary: server,
        useSecondary: false,
        timeout: 4000
      });

      const response = await testResolver.query('syndicate', 'DS');

      res.json({
        ok: response.rcode === 'NOERROR',
        server,
        family: version,
        responseCode: response.rcode,
        answers: (response.answers || []).map(r => ({
          name: r.name,
          type: r.type,
          data: r.data
        }))
      });
    } catch (error) {
      res.status(502).json({ ok: false, server, error: error.message });
    }
  });

  app.get('/api/ca/cert.pem', (req, res) => {
    try {
      res.setHeader('Content-Type', 'application/x-pem-file');
      res.setHeader('Content-Disposition', 'attachment; filename="letsdane-ca.crt"');
      res.send(ca.getPublicCertPem());
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  app.get('/api/ca/cert.der', (req, res) => {
    try {
      res.setHeader('Content-Type', 'application/pkix-cert');
      res.setHeader('Content-Disposition', 'attachment; filename="letsdane-ca.der"');
      res.send(Buffer.from(ca.getPublicCertDer(), 'binary'));
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  app.get('/api/ca/info', (req, res) => {
    res.json(ca.getInfo());
  });

  app.get('/api/health', (req, res) => {
    res.json({ ok: true, timestamp: new Date().toISOString() });
  });

  // Serve the same CA cert with filename="ca.pem" — for users
  // who want the file literally named ca.pem (Brave, manual tools).
  app.get("/api/ca/ca.pem", (req, res) => {
    try {
      res.setHeader("Content-Type", "application/x-pem-file");
      res.setHeader("Content-Disposition", "attachment; filename=\"ca.pem\"");
      res.send(ca.getPublicCertPem());
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  const server = app.listen(port, '127.0.0.1', () => {
    console.log(`Dashboard running at http://127.0.0.1:${port}`);
  });

  server.on('error', error => {
    console.error('[Dashboard]', error.message);
  });

  return { app, server, port };
}
