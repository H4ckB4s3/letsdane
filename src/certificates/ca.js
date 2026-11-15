import forge from 'node-forge';
import fs from 'node:fs/promises';
import path from 'node:path';
import { CA_COMMON_NAME } from '../config/ca-identity.js';

export class LocalCA {
  constructor(dataDir = path.join(process.cwd(), 'data', 'ca')) {
    this.dataDir = dataDir;
    this.certPath = path.join(dataDir, 'certs', 'ca.pem');
    this.keyPath  = path.join(dataDir, 'keys', 'ca.private.key');
    this.cert = null;
    this.privateKey = null;
  }

  async ensure() {
    const certPem = await fs.readFile(this.certPath, 'utf8');
    const keyPem  = await fs.readFile(this.keyPath, 'utf8');

    this.cert = forge.pki.certificateFromPem(certPem);
    this.privateKey = forge.pki.privateKeyFromPem(keyPem);

    const cn = this.cert.subject.getField('CN')?.value;

    if (cn !== CA_COMMON_NAME) {
      throw new Error(
        `CA CN mismatch: found "${cn}", expected "${CA_COMMON_NAME}".\n` +
        `Fix: pkill -f "node src/index.js"; rm -rf data/ca; npm start`
      );
    }

    // Verify the private key matches the certificate public key
    const certPub = forge.pki.publicKeyToPem(this.cert.publicKey);
    const keyDerivedPub = forge.pki.publicKeyToPem(
      forge.pki.setRsaPublicKey(
        this.privateKey.n,
        this.privateKey.e
      )
    );

    if (certPub.replace(/\s+/g, '') !== keyDerivedPub.replace(/\s+/g, '')) {
      throw new Error('CA certificate and private key do not match');
    }

    return { created: false, certPem };
  }

  getPublicCertPem() {
    if (!this.cert) throw new Error('CA not initialized');
    return forge.pki.certificateToPem(this.cert);
  }

  getPublicCertDer() {
    if (!this.cert) throw new Error('CA not initialized');
    return forge.asn1.toDer(forge.pki.certificateToAsn1(this.cert)).getBytes();
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
      issuer:  this.cert.issuer.getField('CN')?.value  || 'Unknown',
      notBefore: this.cert.validity.notBefore,
      notAfter:  this.cert.validity.notAfter,
      serial: this.cert.serialNumber,
      fingerprint: this.getFingerprint()
    };
  }
}
