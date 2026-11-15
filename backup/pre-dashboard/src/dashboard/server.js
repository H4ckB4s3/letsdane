import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Localhost-only dashboard server for Let's DANE JS.
 * Binds exclusively to 127.0.0.1 for security.
 */
export function createDashboard(ca, options = {}) {
  const app = express();
  const port = options.port || 3000;
  const publicDir = path.join(__dirname, '../../public');

  app.use(express.json());
  app.use(express.static(publicDir));

  // API routes - localhost only enforced by bind address
  app.get('/api/status', (req, res) => {
    const info = ca.getInfo();
    res.json({
      proxy: {
        status: options.proxyStatus || 'stopped',
        address: options.proxyAddress || '127.0.0.1:8080'
      },
      dnssec: {
        enabled: true,
        status: 'ready'
      },
      tlsa: {
        enabled: true
      },
      ca: {
        ready: !!info,
        ...info
      }
    });
  });

  app.get('/api/ca/cert.pem', (req, res) => {
    try {
      const pem = ca.getPublicCertPem();
      res.setHeader('Content-Type', 'application/x-pem-file');
      res.setHeader('Content-Disposition', 'attachment; filename="letsdane-ca.crt"');
      res.send(pem);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/ca/cert.der', (req, res) => {
    try {
      const der = ca.getPublicCertDer();
      res.setHeader('Content-Type', 'application/pkix-cert');
      res.setHeader('Content-Disposition', 'attachment; filename="letsdane-ca.der"');
      res.send(Buffer.from(der, 'binary'));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/ca/info', (req, res) => {
    res.json(ca.getInfo());
  });

  // Placeholder for future DANE checker, logs, settings
  app.get('/api/health', (req, res) => {
    res.json({ ok: true, timestamp: new Date().toISOString() });
  });

  const server = app.listen(port, '127.0.0.1', () => {
    console.log(`Dashboard running at http://127.0.0.1:${port}`);
  });

  return { app, server, port };
}
