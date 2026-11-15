import forge from 'node-forge';
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Generates or loads a local Certificate Authority for Let's DANE.
 * Private key never leaves the local machine.
 */
export class LocalCA {
  constructor(dataDir = path.join(process.cwd(), 'data', 'ca')) {
    this.dataDir = dataDir;
    this.certPath = path.join(dataDir, 'ca.crt');
    this.keyPath = path.join(dataDir, 'ca.key');
    this.cert = null;
    this.privateKey = null;
  }

  async ensure() {
    await fs.mkdir(this.dataDir, { recursive: true, mode: 0o700 });

    try {
      const certPem = await fs.readFile(this.certPath, 'utf8');
      const keyPem = await fs.readFile(this.keyPath, 'utf8');
      this.cert = forge.pki.certificateFromPem(certPem);
      this.privateKey = forge.pki.privateKeyFromPem(keyPem);
      return { created: false, certPem, keyPem };
    } catch {
      return this.generate();
    }
  }

  generate() {
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = crypto.randomBytes(16).toString('hex');
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

    const attrs = [
      { name: 'commonName', value: 'Let\'s DANE Local CA' },
      { name: 'organizationName', value: 'Let\'s DANE JS' },
      { shortName: 'OU', value: 'Local DANE Security Manager' },
      { name: 'countryName', value: 'XX' }
    ];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    cert.setExtensions([
      {
        name: 'basicConstraints',
        cA: true,
        critical: true
      },
      {
        name: 'keyUsage',
        keyCertSign: true,
        cRLSign: true,
        critical: true
      },
      {
        name: 'subjectKeyIdentifier'
      }
    ]);

    cert.sign(keys.privateKey, forge.md.sha256.create());

    const certPem = forge.pki.certificateToPem(cert);
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);

    // Write with restricted permissions
    return fs.writeFile(this.certPath, certPem, { mode: 0o644 })
      .then(() => fs.writeFile(this.keyPath, keyPem, { mode: 0o600 }))
      .then(() => {
        this.cert = cert;
        this.privateKey = keys.privateKey;
        return { created: true, certPem, keyPem };
      });
  }

  getPublicCertPem() {
    if (!this.cert) throw new Error('CA not initialized');
    return forge.pki.certificateToPem(this.cert);
  }

  getPublicCertDer() {
    if (!this.cert) throw new Error('CA not initialized');
    const asn1 = forge.pki.certificateToAsn1(this.cert);
    return forge.asn1.toDer(asn1).getBytes();
  }

  getFingerprint(algo = 'sha256') {
    if (!this.cert) throw new Error('CA not initialized');
    const md = forge.md[algo].create();
    md.update(forge.asn1.toDer(forge.pki.certificateToAsn1(this.cert)).getBytes());
    return md.digest().toHex().match(/.{2}/g).join(':').toUpperCase();
  }

  getInfo() {
    if (!this.cert) return null;
    return {
      subject: this.cert.subject.getField('CN')?.value || 'Unknown',
      issuer: this.cert.issuer.getField('CN')?.value || 'Unknown',
      notBefore: this.cert.validity.notBefore,
      notAfter: this.cert.validity.notAfter,
      serial: this.cert.serialNumber,
      fingerprint: this.getFingerprint()
    };
  }
}
