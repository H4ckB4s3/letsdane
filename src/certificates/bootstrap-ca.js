import forge from 'node-forge';
import fs from 'node:fs';
import path from 'node:path';

import {
  CA_COMMON_NAME,
  CA_ORGANIZATION,
  CA_ORGANIZATIONAL_UNIT,
  CA_COUNTRY,
  CA_STATE,
  CA_LOCALITY
} from '../config/ca-identity.js';

// http-mitm-proxy reads these files from sslCaDir:
//   certs/ca.pem          -> PEM certificate
//   keys/ca.private.key   -> PEM private key
//   keys/ca.public.key    -> PEM public key (detached)
//
// Repair rule: if cert + private key exist but public key is missing,
// derive the public key from the private key (do NOT regenerate the CA).
export function ensureMitmCa(dataDir) {
  const certPath      = path.join(dataDir, 'certs', 'ca.pem');
  const keyPath       = path.join(dataDir, 'keys', 'ca.private.key');
  const publicKeyPath = path.join(dataDir, 'keys', 'ca.public.key');

  fs.mkdirSync(path.dirname(certPath), { recursive: true });
  fs.mkdirSync(path.dirname(keyPath),  { recursive: true });

  const haveCert = fs.existsSync(certPath);
  const haveKey  = fs.existsSync(keyPath);
  const havePub  = fs.existsSync(publicKeyPath);

  if (haveCert && haveKey && havePub) {
    return { created: false, certPath, keyPath, publicKeyPath };
  }

  // Repair path: cert + private key exist, derive public key.
  if (haveCert && haveKey && !havePub) {
    const privateKeyPem = fs.readFileSync(keyPath, 'utf8');
    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
    fs.writeFileSync(
      publicKeyPath,
      forge.pki.publicKeyToPem(publicKey),
      { mode: 0o644 }
    );
    return { created: false, repaired: true, certPath, keyPath, publicKeyPath };
  }

  // Full generation path.
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01' + forge.util.bytesToHex(forge.random.getBytesSync(15));
  cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000);
  cert.validity.notAfter  = new Date(Date.now() + 10 * 365 * 24 * 3600 * 1000);

  const attrs = [
    { name: 'commonName',       value: CA_COMMON_NAME },
    { name: 'countryName',      value: CA_COUNTRY },
    { shortName: 'ST',          value: CA_STATE },
    { name: 'localityName',     value: CA_LOCALITY },
    { name: 'organizationName', value: CA_ORGANIZATION },
    { shortName: 'OU',          value: CA_ORGANIZATIONAL_UNIT }
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true, pathLenConstraint: 0 },
    { name: 'keyUsage', critical: true, keyCertSign: true, cRLSign: true, digitalSignature: true },
    { name: 'subjectKeyIdentifier' }
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  fs.writeFileSync(certPath, forge.pki.certificateToPem(cert), { mode: 0o644 });
  fs.writeFileSync(keyPath,  forge.pki.privateKeyToPem(keys.privateKey), { mode: 0o600 });
  fs.writeFileSync(publicKeyPath, forge.pki.publicKeyToPem(keys.publicKey), { mode: 0o644 });

  return { created: true, certPath, keyPath, publicKeyPath };
}
