import https from 'node:https';
import tls from 'node:tls';

export class DaneHttpsAgent extends https.Agent {
  constructor(securityVerifier, proxyLookup, options = {}) {
    super({ keepAlive: false, ...options });

    if (!securityVerifier || typeof securityVerifier.verifyPeerCertificate !== 'function') {
      throw new Error('DANE security verifier is required');
    }
    if (typeof proxyLookup !== 'function') {
      throw new Error('Handshake-aware proxy lookup is required');
    }

    this.securityVerifier = securityVerifier;
    this.proxyLookup = proxyLookup;
  }

  createConnection(options, callback) {
    const hostname = options.servername || options.host;
    const port = Number(options.port || 443);

    let settled = false;
    const finish = (error, socket) => {
      if (settled) return;
      settled = true;
      if (error) socket?.destroy();
      callback?.(error, socket);
    };

    // Strip server-side cert options: http-mitm-proxy passes the leaf
    // cert/key it will PRESENT to the browser here. We must NOT present
    // them upstream — the origin server rejects unknown client certs
    // with sslv3 alert bad certificate.
    const {
      cert: _dropCert,
      key: _dropKey,
      ca: _dropCa,
      pfx: _dropPfx,
      passphrase: _dropPassphrase,
      rejectUnauthorized: _dropReject,
      ...upstreamOptions
    } = options;

    const socket = tls.connect({
      ...upstreamOptions,
      host: options.host || hostname,
      port,
      lookup: this.proxyLookup,
      servername: hostname,
      ALPNProtocols: ['http/1.1'],
      rejectUnauthorized: false
    });

    socket.once('error', error => finish(error));

    socket.once('secureConnect', async () => {
      try {
        const peer = socket.getPeerCertificate(true);
        if (!peer?.raw) throw new Error('Upstream supplied no certificate');

        const verification = await this.securityVerifier.verifyPeerCertificate(
          hostname, port, peer.raw
        );

        const mode = this.securityVerifier.getTrustMode(hostname);

        // ICANN name without TLSA → pass through, standard CA trust applies
        if (mode === 'iana-dnssec' && verification.tlsa === 'NO_TLSA') {
          const tlsMod = await import('node:tls');
          const mismatch = tlsMod.checkServerIdentity(hostname, peer);
          if (mismatch instanceof Error) {
            throw new Error(`Hostname mismatch: ${mismatch.message}`);
          }
          finish(null, socket);
          return;
        }

        if (verification.spki !== 'MATCH' ||
            verification.interception !== 'VERIFICATION_PASSED') {
          throw new Error(`DANE BLOCKED ${hostname}: ${verification.reason || 'Verification failed'}`);
        }

        console.log(`[DANE] VERIFIED ${hostname}:${port} (${verification.trustMode})`);
        finish(null, socket);

      } catch (error) {
        console.error(`[DANE] BLOCKED ${hostname}:${port}:`, error.message);
        finish(error, socket);
      }
    });

    return socket;
  }
}
