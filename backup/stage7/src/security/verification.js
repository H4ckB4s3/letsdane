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

    this.icannTlds = [];

    this.setIcannTlds(options.icannTlds || []);

    this.dnssec = new DnssecValidator(this.resolver);

    this.cache = options.cache || new VerificationCache({
      maxTtl: 86400
    });
  }

  setIcannTlds(tlds) {
    if (!Array.isArray(tlds)) {
      throw new Error('ICANN TLDs must be an array');
    }

    const normalized = tlds.map(value => {
      const tld = String(value)
        .trim()
        .toLowerCase()
        .replace(/^\./, '');

      if (
        !tld ||
        !/^[a-z0-9-]{1,63}$/.test(tld) ||
        tld.startsWith('-') ||
        tld.endsWith('-')
      ) {
        throw new Error(`Invalid ICANN TLD: ${tld}`);
      }

      return tld;
    });

    this.icannTlds = [...new Set(normalized)];

    this.cache?.clear();
  }

  getTrustMode(hostname) {
    const host = String(hostname || '')
      .trim()
      .toLowerCase()
      .replace(/\.$/, '');

    const labels = host.split('.');
    const tld = labels[labels.length - 1];

    return this.icannTlds.includes(tld)
      ? 'iana-dnssec'
      : 'configured-resolver';
  }

  createResult(hostname, port, trustMode) {
    return {
      hostname,
      port,
      resolver: this.resolver.primary,
      trustMode,
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
    const normalizedHost = String(hostname || '')
      .trim()
      .toLowerCase()
      .replace(/\.$/, '');

    const trustMode = this.getTrustMode(normalizedHost);

    const result = this.createResult(
      normalizedHost,
      port,
      trustMode
    );

    if (
      !normalizedHost ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535 ||
      !certificate
    ) {
      result.reason = 'Invalid hostname, port or certificate';
      return result;
    }

    try {
      const certificateBytes = Buffer.isBuffer(certificate)
        ? certificate
        : Buffer.from(certificate);

      result.peerFingerprint = createHash('sha256')
        .update(certificateBytes)
        .digest('hex');

      const cached = this.cache.get(
        normalizedHost,
        port,
        trustMode
      );

      if (
        cached &&
        cached.peerFingerprint === result.peerFingerprint
      ) {
        return {
          ...cached,
          hostname: normalizedHost,
          port,
          trustMode,
          cached: true
        };
      }

      if (cached) {
        this.cache.delete(normalizedHost, port, trustMode);
      }

      const validation = await this.dnssec.verifyTLSA(
        normalizedHost,
        port,
        'tcp',
        trustMode
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

      result.tlsa = trustMode === 'iana-dnssec'
        ? 'DNSSEC_AUTHENTICATED'
        : 'RESOLVER_SUPPLIED';

      if (!TlsaValidator.validateDaneEE(
        certificateBytes,
        validation.records
      )) {
        result.spki = 'MISMATCH';
        throw new Error(
          'Upstream certificate does not match TLSA records'
        );
      }

      result.spki = 'MATCH';

      result.handshake = trustMode === 'iana-dnssec'
        ? 'DNSSEC_VERIFIED'
        : 'TRUSTED_RESOLVER';

      result.interception = 'VERIFICATION_PASSED';
      result.cacheTtl = validation.ttlSeconds;

      result.reason =
        'Upstream certificate matches TLSA association. ' +
        `Trust mode: ${trustMode}.`;

      this.cache.set(
        normalizedHost,
        port,
        trustMode,
        result,
        validation.ttlSeconds
      );

      return result;

    } catch (error) {
      this.cache.delete(normalizedHost, port, trustMode);

      result.reason = error.message;
      result.interception = 'BLOCKED';

      return result;
    }
  }

  async verify(hostname, port = 443) {
    const normalizedHost = String(hostname || '')
      .trim()
      .toLowerCase()
      .replace(/\.$/, '');

    const trustMode = this.getTrustMode(normalizedHost);

    const result = this.createResult(
      normalizedHost,
      port,
      trustMode
    );

    if (
      !normalizedHost ||
      normalizedHost.length > 253 ||
      !/^[a-zA-Z0-9.-]+$/.test(normalizedHost) ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535
    ) {
      result.reason = 'Invalid hostname or port';
      return result;
    }

    try {
      const response = await this.resolver.query(
        normalizedHost,
        'A'
      );

      if (response.rcode !== 'NOERROR') {
        throw new Error(`DNS lookup failed: ${response.rcode}`);
      }

      const address = (response.answers || [])
        .find(record => record.type === 'A')?.data;

      if (!address || isIP(address) !== 4) {
        throw new Error('No valid upstream IPv4 address returned');
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
      this.cache.delete(normalizedHost, port, trustMode);

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

        if (error) reject(error);
        else resolve(certificate);
      };

      socket.once('secureConnect', () => {
        try {
          const peerCertificate = socket.getPeerCertificate(true);

          if (!peerCertificate?.raw) {
            throw new Error('Upstream provided no certificate');
          }

          finish(null, peerCertificate.raw);
        } catch (error) {
          finish(error);
        }
      });

      socket.once('error', error => finish(error));

      socket.once('timeout', () => {
        finish(new Error('Upstream TLS timeout'));
      });
    });
  }
}
