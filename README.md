# Let's DANE JS

Local DANE (DNS-Based Authentication of Named Entities) security manager.

Pure Node.js local proxy that enables DANE-EE in browsers. Runs entirely on your computer.

**Status:** Stages 1–5 scaffolded. DNSSEC full crypto validation and production proxy hardening pending library integration. Use at your own risk.

## Security Model (enforced)

- CA private key never leaves the local machine (mode 0600).
- Dashboard and proxy bind only to `127.0.0.1`.
- Only the public CA certificate is downloadable.
- DNSSEC must be cryptographically validated (AD flag alone is not trusted).
- DNSSEC or TLSA failure is **fail-closed** — no silent fallback to ordinary CA validation.
- Not an open proxy.

## Quick Start

```bash
cd letsdane-js
npm install          # express, node-forge, http-mitm-proxy
npm start
```

- Dashboard: http://127.0.0.1:3000
- Proxy: http://127.0.0.1:8080
- CA download: http://127.0.0.1:3000/api/ca/cert.pem
- Install guide: http://127.0.0.1:3000/install.html

## Primary Target

**Firefox-first.** Import the CA into Firefox’s own certificate store. Other browsers and OS trust stores come later.

## Modules

- `src/certificates/ca.js` — local CA generation/persistence
- `src/dns/resolver.js` — DoH resolver with DO bit
- `src/dns/dnssec.js` — DNSSEC validation interface (fail-closed stub; integrate @namefi/dnssec-audit or dnsfence)
- `src/dns/tlsa.js` — DANE-EE matching (RFC 6698/7671)
- `src/proxy/http-proxy.js` — local MITM proxy (only on successful DANE)
- `src/dashboard/` + `public/` — localhost dashboard + install guide

## Remaining work

- Wire a pure-JS DNSSEC library for full chain validation.
- Complete upstream cert fetch + DANE-EE comparison before generating local cert.
- Security tests, packaging (`npx letsdane-js`), and broader browser/OS docs.

## Original reference

Functional security model from [Let's DANE](https://github.com/buffrr/letsdane) (Go).

## License

Apache-2.0
