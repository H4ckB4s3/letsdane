import { Proxy } from 'http-mitm-proxy';
import path from 'node:path';

import { DaneHttpsAgent } from '../security/dane-https-agent.js';

export class DaneProxy {
  constructor(ca, options = {}) {
    this.ca = ca;
    this.port = options.port ?? 8080;
    this.securityVerifier = options.securityVerifier;

    if (
      !this.securityVerifier ||
      typeof this.securityVerifier.verifyPeerCertificate !== 'function'
    ) {
      throw new Error('DANE verification is mandatory');
    }

    this.httpsAgent = new DaneHttpsAgent(
      this.securityVerifier
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

    console.log('[DANE] HTTPS agent attached.');
    console.log('[DANE] Certificate issuance fail-closed.');
  }

  async stop() {
    if (!this.started) return;

    await new Promise(resolve => {
      this.proxy.close(() => resolve());
    });

    this.httpsAgent.destroy();
    this.started = false;

    console.log('[Proxy] Stopped.');
  }
}
