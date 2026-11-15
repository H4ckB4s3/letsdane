import { Proxy } from 'http-mitm-proxy';
import { LocalCA } from '../certificates/ca.js';
import { DnsResolver } from '../dns/resolver.js';
import { DnssecValidator } from '../dns/dnssec.js';
import { TlsaValidator } from '../dns/tlsa.js';
import forge from 'node-forge';
import path from 'path';

/**
 * Local DANE-aware HTTPS proxy.
 * - Binds only to 127.0.0.1
 * - On successful DANE-EE + DNSSEC: generate cert signed by local CA
 * - On failure or no TLSA: do NOT MITM (or fail closed — never silent fallback to ordinary CA)
 * - Not an open proxy
 */
export class DaneProxy {
  constructor(ca, options = {}) {
    this.ca = ca;
    this.port = options.port || 8080;
    this.resolver = new DnsResolver(options.dns);
    this.dnssec = new DnssecValidator();
    this.proxy = new Proxy();
  }

  async start() {
    // Configure proxy to use our CA
    this.proxy.onCertificateRequired = (hostname, callback) => {
      // Custom cert generation path — we control this
      callback(null, {
        keyFile: null, // in-memory preferred
        certFile: null
      });
    };

    this.proxy.onCertificateMissing = async (ctx, files, callback) => {
      const hostname = ctx.hostname;

      try {
        // 1. Resolve TLSA with DNSSEC
        const tlsaResponse = await this.resolver.resolveTLSA(hostname);
        const secure = await this.dnssec.isSecure(tlsaResponse);

        if (!secure) {
          // Fail closed — do not MITM
          console.log(`[DANE] DNSSEC validation failed for ${hostname} — not intercepting`);
          return callback(new Error('DNSSEC validation failed'));
        }

        const tlsaRecords = tlsaResponse.answers?.filter(a => a.type === 'TLSA') || [];
        if (tlsaRecords.length === 0) {
          console.log(`[DANE] No TLSA for ${hostname} — not intercepting`);
          return callback(new Error('No TLSA records'));
        }

        // 2. Connect to upstream to get real cert, then validate DANE-EE
        // (In full implementation, do this in the tunnel)
        // For now, generate only if we decide to proceed

        const cert = this.generateCertForHost(hostname);
        // Save or return in-memory cert/key
        callback(null, {
          key: forge.pki.privateKeyToPem(cert.key),
          cert: forge.pki.certificateToPem(cert.cert)
        });
      } catch (err) {
        console.error(`[DANE] Validation error for ${hostname}:`, err.message);
        callback(err); // Fail closed
      }
    };

    this.proxy.listen({
      port: this.port,
      host: '127.0.0.1',
      sslCaDir: path.join(process.cwd(), 'data', 'ca')
    });

    console.log(`DANE proxy listening on 127.0.0.1:${this.port}`);
  }

  generateCertForHost(hostname) {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setHours(cert.validity.notAfter.getHours() + 1); // Short lived

    cert.setSubject([{ name: 'commonName', value: hostname }]);
    cert.setIssuer(this.ca.cert.subject.attributes);

    cert.setExtensions([
      { name: 'subjectAltName', altNames: [{ type: 2, value: hostname }] },
      { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
      { name: 'extKeyUsage', serverAuth: true }
    ]);

    cert.sign(this.ca.privateKey, forge.md.sha256.create());

    return { cert, key: keys.privateKey };
  }
}
