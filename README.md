Copy everything below into a file named `README.md`.

markdown

````markdown

# LetsDANE JS

A local DANE (DNS-Based Authentication of Named Entities) security manager for Handshake (HNS) and ICANN namespaces, written in pure Node.js.

LetsDANE runs a localhost-only HTTPS proxy that enforces DANE-EE TLSA verification for Handshake names, falls through to standard CA validation for ICANN names without TLSA records, and exposes a dashboard for resolver configuration and live verification status.

---

## Status

### Working today

- Handshake-rooted DNSSEC/DANE HTTPS (DANE-EE, usage 3, selector 1).
- Wildcard TLSA lookup for HNS second-level names (`_443._tcp.*.tld`).
- ICANN names pass through to standard CA validation (no TLSA required).
- Configurable primary/secondary resolvers via dashboard.
- Local `hsd` / `hnsd` node support (address + port).
- Persistent settings in `data/settings.json`.
- Live verification log at `/api/security/recent`.
- Local CA identity `Non Slave Root CA`, generated on first run.

### Not implemented yet

- Leaf certificate O/OU override (leaves currently show the `http-mitm-proxy` default `Node MITM Proxy CA` strings).
- Independent Handshake blockchain trust verification (resolver answers are treated as trusted for HNS names; a separate HNS trust provider is planned).

> **Note:** Treat this as a functional working prototype, not a hardened security product.

---

## Architecture

```text
Browser (Firefox / Brave)
        |
        v
HTTP/HTTPS proxy on 127.0.0.1:8080
        |
        v
+----------------------------------------------+
| DaneProxy (http-mitm-proxy)                  |
|                                              |
|  +-- Leaf cert signed by LocalCA             |
|  +-- DaneHttpsAgent (upstream TLS client)     |
|       |                                      |
|       +-- proxyLookup (splits HNS vs ICANN)  |
|       +-- TLSA lookup via DnsResolver        |
|       +-- DnssecValidator                    |
|       +-- TlsaValidator (SPKI SHA-256 match) |
+----------------------------------------------+
        |
        v
UDP/53 (or local node on 5350)
        |
        v
HNS resolver (e.g. 82.68.70.162)
        |
        v
Handshake blockchain + delegated DNSSEC zone
```

### Trust rules

| Name class | TLSA present | Behaviour |
|---|---|---|
| HNS (e.g. `syndicate`) | Yes | Require TLSA match, otherwise block |
| HNS | No | Block (fail-closed) |
| ICANN | Yes | Require TLSA match, otherwise block |
| ICANN | No | Standard CA validation via OS resolver |

The ICANN TLD list is editable in the dashboard. Additions and removals take effect immediately without restarting the application.

---

## Requirements

- Node.js **18 or newer**.
- A Handshake-aware DNS resolver reachable over UDP/53, or a local `hsd` / `hnsd` node exposing DNS on a port (default `5350`).
- Firefox or Brave for the client side.

---

## Installation

Clone the repository and install dependencies:

```bash
git clone <your-fork> letsdane-js
cd letsdane-js
npm install
```

### First start

The first start generates a fresh local CA at `data/ca/` with the Common Name:

```text
Non Slave Root CA
```

Start the application:

```bash
npm start
```

You should see:

```text
✓ Generated fresh CA (Non Slave Root CA)
CA fingerprint: <hex>
DANE proxy listening on 127.0.0.1:8080
Dashboard running at http://127.0.0.1:3000
```

Subsequent starts print:

```text
✓ Loaded existing CA with the same fingerprint
```

To rotate the CA:

```bash
rm -rf data/ca && npm start
```

---

## Dashboard

Open the dashboard at:

**http://127.0.0.1:3000**

### Dashboard sections

#### Proxy

- Current listen address.
- CA status.

#### Certificate downloads

Three formats are available for different browsers and operating systems:

| Format | Encoding | Intended use |
|---|---|---|
| `.crt` | PEM | Firefox (`letsdane-ca.crt`) |
| `.der` | DER | Android / system trust stores |
| `.pem` | PEM | Brave (`ca.pem`) |

#### DNS Trust & Resolvers

- Active resolver selector (saved profiles).
- Add and save new resolvers (label + IPv4/IPv6).
- Secondary resolver and failover toggle.
- Local `hsd` / `hnsd` node configuration (address + port, default `127.0.0.1:5350`).
- Per-resolver **Test** button that performs a live `syndicate` DS lookup.

#### ICANN TLDs

- Chip editor with add/remove functionality.
- Bulk CSV/TXT upload.

#### Live verification

Rolling table of recent DANE outcomes:

- `DANE ✓`
- `ICANN pass`
- `Blocked`

Each entry includes a reason.

Settings persist in `data/settings.json` (mode `0600`).

The default Handshake resolver (`82.68.70.162`) is always kept as a selectable option.

---

## Browser Installation

See `/install.html` in the dashboard for the full installation guide.

### Firefox

1. Download `letsdane-ca.crt` from the dashboard.
2. Open:

   ```text
   about:preferences#connectionSecurity
   ```

3. Navigate to **View Certificates → Authorities → Import**.
4. Import the downloaded certificate and enable trust for websites.
5. Open **Network Settings → Settings**.
6. Configure the manual proxy:

   | Setting | Value |
   |---|---|
   | HTTP Proxy | `127.0.0.1` |
   | HTTP Port | `8080` |
   | HTTPS Proxy | `127.0.0.1` |
   | HTTPS Port | `8080` |

7. Restart Firefox.

### Brave

1. Download `ca.pem` from the dashboard.
2. Open:

   ```text
   brave://certificate-manager/
   ```

3. Navigate to **Authorities → Import**.
4. Import the downloaded certificate and enable trust for websites.
5. Configure your OS proxy settings:

   | Setting | Value |
   |---|---|
   | HTTP Proxy | `127.0.0.1:8080` |
   | HTTPS Proxy | `127.0.0.1:8080` |

6. Restart Brave.

> **Note:** Brave (like Chrome) may also require enabling the "Use system trust store" option or installing the CA into the OS trust store. Both approaches work.

---

## Using a Local `hsd` / `hnsd` Node

If you run a local Handshake full node that exposes DNS over UDP/TCP, enable **Use local hsd / hnsd node** in the dashboard and configure its address and port.

### Typical ports

| Software | Port | Example invocation |
|---|---:|---|
| `hnsd` | `5350` | `hnsd -r 127.0.0.1:5350` |
| `hsd` | `5350` | `hsd --rs-port 5350` |

### Verify connectivity

Run:

```bash
dig @127.0.0.1 -p 5350 syndicate DS +dnssec
```

The resolver uses the following priority:

1. Local node, if enabled.
2. Active configured resolver.
3. Secondary resolver, if enabled and required.

---

## Configuration

Settings are stored in:

```text
data/settings.json
```

Default configuration:

```json
{
  "activeResolver": "82.68.70.162",
  "resolverProfiles": [
    {
      "label": "Handshake resolver",
      "ip": "82.68.70.162"
    }
  ],
  "useSecondary": false,
  "secondary": "",
  "timeout": 5000,
  "useLocalNode": false,
  "localNodeAddress": "127.0.0.1",
  "localNodePort": 5350,
  "icannTlds": [
    "com",
    "net",
    "org",
    "..."
  ]
}
```

The settings file is managed by the dashboard.

Editing it manually is supported, but `npm start` validates its structure on load and rewrites defaults for missing fields.

---

## API

All endpoints are bound to `127.0.0.1` only.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/status` | Proxy, CA, resolver summary |
| `GET` | `/api/settings` | Current settings |
| `PUT` | `/api/settings` | Save settings, applies immediately |
| `POST` | `/api/resolvers/test` | Live DS lookup against a given IPv4/IPv6 |
| `POST` | `/api/security/verify` | Run a one-off DANE verification for a hostname |
| `GET` | `/api/security/status` | Current verification state |
| `GET` | `/api/security/recent` | Last 200 proxy verifications |
| `GET` | `/api/ca/info` | CA subject, issuer, validity, fingerprint |
| `GET` | `/api/ca/cert.pem` | PEM, filename `letsdane-ca.crt` |
| `GET` | `/api/ca/ca.pem` | PEM, filename `ca.pem` |
| `GET` | `/api/ca/cert.der` | DER, filename `letsdane-ca.der` |
| `GET` | `/api/health` | Liveness |

---

## Project Structure

```text
letsdane-js/
│
├── src/
│   ├── certificates/
│   │   ├── bootstrap-ca.js     # Creates data/ca with correct identity
│   │   └── ca.js               # Loads + asserts CN on every start
│   │
│   ├── config/
│   │   ├── ca-identity.js      # Single source of truth for CA name
│   │   └── settings.js         # Persistent settings with validation + migration
│   │
│   ├── dashboard/
│   │   └── server.js           # Express app, all API routes
│   │
│   ├── dns/
│   │   ├── resolver.js         # UDP DNS with primary/secondary/local-node failover
│   │   ├── dnssec.js           # DNSSEC validation via @relaycorp/dnssec
│   │   └── tlsa.js             # TLSA parser + SPKI SHA-256 matcher
│   │
│   ├── proxy/
│   │   └── http-proxy.js       # http-mitm-proxy wrapper, binds 127.0.0.1 only
│   │
│   ├── security/
│   │   ├── dane-https-agent.js # Upstream TLS client enforcing DANE
│   │   ├── proxy-lookup.js     # Split DNS: OS resolver for ICANN, HNS otherwise
│   │   └── verification.js     # Per-host verification with cache
│   │
│   └── index.js                # Entry point, wires everything
│
├── public/
│   ├── index.html              # Dashboard
│   ├── install.html             # Browser setup guide
│   ├── app.js
│   └── style.css
│
├── data/
│   ├── settings.json           # Created on first run
│   └── ca/                     # CA cert, key, and generated leaf certs
│
├── package.json
├── package-lock.json
└── README.md
```

---

## Security Notes

### Localhost-only binding

The proxy and dashboard bind to `127.0.0.1` only.

### CA private key

The CA private key never leaves the machine. Only the public certificate is downloadable.

### DANE verification

DANE failures are fail-closed: if a TLSA record exists and the upstream certificate does not match, the connection is refused.

### ICANN fallback

ICANN names without TLSA records fall back to standard CA validation.

This is deliberate; otherwise every non-DANE site would be blocked.

### Handshake trust model

HNS trust is currently resolver-based.

The configured HNS resolver is trusted to return correct answers for HNS names. Independent Handshake blockchain verification is not implemented yet.

For high-assurance use, point the resolver at your own `hsd` full node via the local-node option.

### Leaf certificate identity

The leaf certificate subject still shows `Node MITM Proxy CA` as Organization/OU because `http-mitm-proxy@1.1.0` hardcodes those fields.

The issuer is correctly `Non Slave Root CA`, which is what browsers display in the trust chain.

A cosmetic override is planned.

---

## Roadmap

- [ ] Override leaf O/OU to match local CA identity.
- [ ] Independent HNS blockchain trust provider (Urkel proof against `hsd`).
- [ ] DNSSEC validation for HNS child zones (currently resolver-trusted).
- [ ] macOS / Windows proxy auto-configuration helper.
- [ ] Optional local CA export as `.p12` for easier import on some platforms.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

---

## Acknowledgements

- [http-mitm-proxy](https://github.com/joeferner/node-http-mitm-proxy)
- [@relaycorp/dnssec](https://github.com/relaycorp/dnssec)
- [Handshake](https://handshake.org/) and the `hsd` / `hnsd` reference nodes.
- `handshake-volume-resolver`
````
