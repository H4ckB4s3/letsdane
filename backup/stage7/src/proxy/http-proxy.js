import { Proxy } from 'http-mitm-proxy';
import path from 'node:path';
import http from 'node:http';

import { DaneHttpsAgent } from '../security/dane-https-agent.js';

export class DaneProxy {
  constructor(ca, options = {}) {
    this.ca = ca;
    this.port = options.port ?? 8080;

    this.resolver = options.resolver;
    this.securityVerifier = options.securityVerifier;

    if (
      !this.resolver ||
      typeof this.resolver.lookup !== 'function'
    ) {
      throw new Error(
        'Handshake-aware DNS resolver is mandatory'
      );
    }

    if (
      !this.securityVerifier ||
      typeof this.securityVerifier.verifyPeerCertificate !== 'function'
    ) {
      throw new Error(
        'DANE verification is mandatory'
      );
    }

    this.httpAgent = new http.Agent({
      keepAlive: false,
      lookup: this.resolver.lookup.bind(this.resolver)
    });

    this.httpsAgent = new DaneHttpsAgent(
      this.securityVerifier,
      this.resolver
    );

    this.proxy = new Proxy();
    this.started = false;
  }

  async start() {
    if (this.started) return;

    this.proxy.onError((ctx, error, kind) => {
      console.error(
        `[Proxy] ${kind || 'ERROR'}:`,
        error?.message || error
      );
    });

    await new Promise((resolve, reject) => {
      this.proxy.listen(
        {
          port: this.port,
          host: '127.0.0.1',

          sslCaDir: path.join(
            process.cwd(),
            'data',
            'ca'
          ),

          httpAgent: this.httpAgent,
          httpsAgent: this.httpsAgent,

          keepAlive: false
        },
        error => {
          if (error) reject(error);
          else resolve();
        }
      );
    });

    this.started = true;

    console.log(
      `DANE proxy listening on 127.0.0.1:${this.port}`
    );

    console.log(
      '[DNS] HTTP upstream uses configured resolver.'
    );

    console.log(
      '[DNS] HTTPS upstream uses configured resolver.'
    );

    console.log(
      '[DANE] HTTPS certificate verification is mandatory.'
    );

    console.log(
      '[DANE] Certificate issuance fail-closed.'
    );
  }

  async stop() {
    if (!this.started) return;

    await new Promise(resolve => {
      this.proxy.close(() => resolve());
    });

    this.httpAgent.destroy();
    this.httpsAgent.destroy();

    this.started = false;

    console.log('[Proxy] Stopped.');
  }
}
