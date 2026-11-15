import crypto from 'crypto';
import forge from 'node-forge';

/**
 * TLSA record parsing and DANE-EE (usage 3) validation per RFC 6698 / RFC 7671.
 * Fail closed: any validation failure rejects the connection.
 */
export class TlsaValidator {
  /**
   * Match a certificate against TLSA records (DANE-EE focus).
   * @param {Buffer|string} certPem or der
   * @param {Array} tlsaRecords - from DNS
   * @returns {boolean} true only if fully matches a valid DANE-EE record
   */
  static validateDaneEE(certPem, tlsaRecords) {
    if (!tlsaRecords || tlsaRecords.length === 0) {
      return false; // No TLSA = not DANE
    }

    const cert = typeof certPem === 'string'
      ? forge.pki.certificateFromPem(certPem)
      : forge.pki.certificateFromAsn1(forge.asn1.fromDer(certPem));

    const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const spki = forge.asn1.toDer(forge.pki.publicKeyToAsn1(cert.publicKey)).getBytes();

    for (const rr of tlsaRecords) {
      // rr.data for TLSA: usage, selector, matchingType, certificateAssociationData
      const { usage, selector, matchingType, certificateAssociationData } = rr.data || rr;

      // Only support DANE-EE (usage = 3) for now
      if (usage !== 3) continue;

      let dataToHash;
      if (selector === 0) {
        dataToHash = Buffer.from(certDer, 'binary'); // Full cert
      } else if (selector === 1) {
        dataToHash = Buffer.from(spki, 'binary'); // SPKI
      } else {
        continue;
      }

      let computed;
      if (matchingType === 0) {
        computed = dataToHash; // Full
      } else if (matchingType === 1) {
        computed = crypto.createHash('sha256').update(dataToHash).digest();
      } else if (matchingType === 2) {
        computed = crypto.createHash('sha512').update(dataToHash).digest();
      } else {
        continue;
      }

      const association = Buffer.from(certificateAssociationData);
      if (computed.equals(association)) {
        return true; // Valid DANE-EE match
      }
    }

    return false;
  }

  /**
   * Strict: returns true only on successful DANE-EE match.
   * Caller must fail the connection on false.
   */
  static isValid(cert, tlsaRecords) {
    return this.validateDaneEE(cert, tlsaRecords);
  }
}
