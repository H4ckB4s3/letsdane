import forge from 'node-forge';
import fs from 'node:fs/promises';
import path from 'node:path';

export class LocalCA {
  constructor(dataDir = path.join(process.cwd(), 'data', 'ca')) {
    this.dataDir = dataDir;

    // Use the actual http-mitm-proxy CA.
    this.certPath = path.join(
      dataDir,
      'certs',
      'ca.pem'
    );

    this.keyPath = path.join(
      dataDir,
      'keys',
      'ca.private.key'
    );

    this.cert = null;
    this.privateKey = null;
  }

  async ensure() {
    const certPem = await fs.readFile(
      this.certPath,
      'utf8'
    );

    const keyPem = await fs.readFile(
      this.keyPath,
      'utf8'
    );

    this.cert = forge.pki.certificateFromPem(certPem);
    this.privateKey = forge.pki.privateKeyFromPem(keyPem);

    if (!this.cert || !this.privateKey) {
      throw new Error('Proxy CA initialization failed');
    }

    return {
      created: false,
      certPem
    };
  }

  getPublicCertPem() {
    if (!this.cert) {
      throw new Error('CA not initialized');
    }

    return forge.pki.certificateToPem(this.cert);
  }

  getPublicCertDer() {
    if (!this.cert) {
      throw new Error('CA not initialized');
    }

    const asn1 = forge.pki.certificateToAsn1(this.cert);

    return forge.asn1.toDer(asn1).getBytes();
  }

  getFingerprint(algo = 'sha256') {
    if (!this.cert) {
      throw new Error('CA not initialized');
    }

    const md = forge.md[algo].create();

    md.update(
      forge.asn1.toDer(
        forge.pki.certificateToAsn1(this.cert)
      ).getBytes()
    );

    return md.digest()
      .toHex()
      .match(/.{2}/g)
      .join(':')
      .toUpperCase();
  }

  getInfo() {
    if (!this.cert) {
      return null;
    }

    return {
      subject:
        this.cert.subject.getField('CN')?.value || 'Unknown',

      issuer:
        this.cert.issuer.getField('CN')?.value || 'Unknown',

      notBefore: this.cert.validity.notBefore,
      notAfter: this.cert.validity.notAfter,
      serial: this.cert.serialNumber,
      fingerprint: this.getFingerprint()
    };
  }
}
