import tls from 'node:tls';
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';

import { DnsResolver } from '../dns/resolver.js';
import { DnssecValidator } from '../dns/dnssec.js';
import { TlsaValidator } from '../dns/tlsa.js';
import { VerificationCache } from './verification-cache.js';

export class SecurityVerification {
  constructor(options = {}) {
    this.resolver = options.resolver || new DnsResolver({
      ...options.dns,
      useSecondary: false
    });

    this.trustMode = options.trustMode || 'iana-dnssec';

    this.dnssec = new DnssecValidator(this.resolver, {
      trustMode: this.trustMode
    });

    this.cache = options.cache || new VerificationCache({
      maxTtl: 86400
    });
  }

  createResult(hostname, port) {
    return {
      hostname,
      port,
      resolver: this.resolver.primary,
      trustMode: this.trustMode,
      dnssec: 'NOT_TESTED',
      tlsa: 'NOT_TESTED',
      spki: 'NOT_TESTED',
      handshake: 'UNVERIFIED',
      interception: 'BLOCKED',
      upstreamIP: null,
      peerFingerprint: null,
      cached: false,
      cacheTtl: null,
      reason: null
    };
  }

  async verifyPeerCertificate(hostname, port = 443, certificate) {
    const result = this.createResult(hostname, port);

    if (
      typeof hostname !== 'string' ||
      !hostname.trim() ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535 ||
      !certificate
    ) {
      result.reason = 'Invalid hostname, port or certificate';
      return result;
    }

    const normalizedHost = hostname
      .trim()
      .toLowerCase()
      .replace(/\.$/, '');

    try {
      const certificateBytes = Buffer.isBuffer(certificate)
        ? certificate
        : Buffer.from(certificate);

      const peerFingerprint = createHash('sha256')
        .update(certificateBytes)
        .digest('hex');

      result.peerFingerprint = peerFingerprint;

      const cached = this.cache.get(
        normalizedHost,
        port,
        this.trustMode
      );

      // A cached result is valid only for the exact same
      // upstream certificate.
      if (cached && cached.peerFingerprint === peerFingerprint) {
        return {
          ...cached,
          hostname: normalizedHost,
          port,
          cached: true
        };
      }

      // A different certificate must never inherit
      // a previous successful verification.
      if (cached) {
        this.cache.delete(
          normalizedHost,
          port,
          this.trustMode
        );
      }

      const validation = await this.dnssec.verifyTLSA(
        normalizedHost,
        port,
        'tcp'
      );

      result.dnssec = validation.status.toUpperCase();

      if (!validation.valid) {
        throw new Error(
          `TLSA/DNSSEC verification failed: ${validation.reason}`
        );
      }

      if (!validation.records?.length) {
        throw new Error('No TLSA records available');
      }

      result.tlsa = this.trustMode === 'iana-dnssec'
        ? 'DNSSEC_AUTHENTICATED'
        : 'RESOLVER_SUPPLIED';

      const matches = TlsaValidator.validateDaneEE(
        certificateBytes,
        validation.records
      );

      if (!matches) {
        result.spki = 'MISMATCH';

        throw new Error(
          'Upstream certificate does not match TLSA records'
        );
      }

      result.spki = 'MATCH';

      result.handshake = this.trustMode === 'iana-dnssec'
        ? 'DNSSEC_VERIFIED'
        : 'TRUSTED_RESOLVER';

      result.interception = 'VERIFICATION_PASSED';
      result.cacheTtl = validation.ttlSeconds;

      result.reason =
        'Upstream certificate matches the TLSA association. ' +
        `Trust mode: ${this.trustMode}.`;

      this.cache.set(
        normalizedHost,
        port,
        this.trustMode,
        result,
        validation.ttlSeconds
      );

      return result;

    } catch (error) {
      this.cache.delete(
        normalizedHost,
        port,
        this.trustMode
      );

      result.reason = error.message;
      result.interception = 'BLOCKED';

      return result;
    }
  }

  async verify(hostname, port = 443) {
    const result = this.createResult(hostname, port);

    if (
      typeof hostname !== 'string' ||
      !hostname.trim() ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535
    ) {
      result.reason = 'Invalid hostname or port';
      return result;
    }

    const normalizedHost = hostname
      .trim()
      .toLowerCase()
      .replace(/\.$/, '');

    try {
      const response = await this.resolver.query(
        normalizedHost,
        'A'
      );

      if (response.rcode !== 'NOERROR') {
        throw new Error(
          `DNS lookup failed: ${response.rcode}`
        );
      }

      const address = (response.answers || [])
        .find(record => record.type === 'A')?.data;

      if (!address || isIP(address) !== 4) {
        throw new Error(
          'No valid upstream IPv4 address returned'
        );
      }

      result.upstreamIP = address;

      const certificate = await this.getCertificate(
        address,
        normalizedHost,
        port
      );

      const verification = await this.verifyPeerCertificate(
        normalizedHost,
        port,
        certificate
      );

      return {
        ...verification,
        upstreamIP: address
      };

    } catch (error) {
      this.cache.delete(
        normalizedHost,
        port,
        this.trustMode
      );

      result.reason = error.message;
      result.interception = 'BLOCKED';

      return result;
    }
  }

  getCertificate(address, hostname, port) {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({
        host: address,
        port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 8000
      });

      let settled = false;

      const finish = (error, certificate) => {
        if (settled) return;
        settled = true;

        socket.destroy();

        if (error) {
          reject(error);
        } else {
          resolve(certificate);
        }
      };

      socket.once('secureConnect', () => {
        try {
          const peerCertificate = socket.getPeerCertificate(true);

          if (!peerCertificate?.raw) {
            throw new Error(
              'Upstream provided no certificate'
            );
          }

          finish(null, peerCertificate.raw);

        } catch (error) {
          finish(error);
        }
      });

      socket.once('error', error => {
        finish(error);
      });

      socket.once('timeout', () => {
        finish(new Error('Upstream TLS timeout'));
      });
    });
  }
}
