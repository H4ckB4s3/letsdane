import dnsPacket from 'dns-packet';
import dgram from 'node:dgram';
import { randomInt } from 'node:crypto';

const TYPE_MAP = {
  A: 1, NS: 2, CNAME: 5, SOA: 6,
  PTR: 12, MX: 15, TXT: 16, AAAA: 28,
  SRV: 33, DS: 43, RRSIG: 46, NSEC: 47,
  DNSKEY: 48, NSEC3: 50, TLSA: 52
};

export class DnsResolver {
  constructor(options = {}) {
    this.primary = options.activeResolver || options.primary || '82.68.70.162';
    this.secondary = options.secondary || '';
    this.useSecondary = options.useSecondary ?? false;
    this.timeout = options.timeout ?? 5000;
    this.port = options.port ?? 53;
    this.useLocalNode = options.useLocalNode === true;
    this.localNodeAddress = options.localNodeAddress || '127.0.0.1';
    this.localNodePort = Number(options.localNodePort) || 5350;
    this.activeServer = null;
    this.verbose = options.verbose !== false;

    // Track local node health so we don't stall every query if it's dead
    this._localNodeDead = false;
    this._localNodeRetryAt = 0;
  }

  get targets() {
    const list = [];

    if (this.useLocalNode) {
      // Only skip local if it recently failed hard
      const now = Date.now();
      if (!this._localNodeDead || now >= this._localNodeRetryAt) {
        list.push({
          address: this.localNodeAddress,
          port: this.localNodePort,
          label: `local(${this.localNodeAddress}:${this.localNodePort})`,
          isLocal: true
        });
      }
    }

    list.push({ address: this.primary, port: this.port, label: this.primary });
    if (this.useSecondary && this.secondary) {
      list.push({ address: this.secondary, port: this.port, label: this.secondary });
    }
    return list;
  }

  get servers() {
    return this.targets.map(t => t.address);
  }

  async queryWire(name, type = 'A') {
    const typeName = typeof type === 'string'
      ? type.toUpperCase()
      : Object.keys(TYPE_MAP).find(k => TYPE_MAP[k] === type);

    if (!typeName || !TYPE_MAP[typeName]) throw new Error(`Unsupported DNS type: ${type}`);

    const normalizedName = name.endsWith('.') ? name : `${name}.`;
    const id = randomInt(0, 65536);

    const packet = dnsPacket.encode({
      type: 'query',
      id,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{ type: typeName, name: normalizedName, class: 'IN' }],
      additionals: [{
        type: 'OPT',
        name: '.',
        udpPayloadSize: 1232,
        flags: dnsPacket.DNSSEC_OK,
        options: []
      }]
    });

    let lastError;

    for (const target of this.targets) {
      const start = Date.now();
      // Local node gets a fast timeout so we don't stall on a dead hnsd
      const effectiveTimeout = target.isLocal ? 800 : this.timeout;

      try {
        const response = await this.sendQuery(target.address, target.port, packet, id, effectiveTimeout);
        const decoded = dnsPacket.decode(response);
        const question = decoded.questions?.[0];

        if (
          decoded.id !== id ||
          decoded.type !== 'response' ||
          decoded.questions?.length !== 1 ||
          question.type !== typeName ||
          question.name.replace(/\.$/, '').toLowerCase() !==
            normalizedName.replace(/\.$/, '').toLowerCase()
        ) {
          throw new Error('Invalid DNS response');
        }

        if (decoded.flags & dnsPacket.TRUNCATED_RESPONSE) {
          throw new Error('Truncated DNS response');
        }

        if (target.isLocal) {
          this._localNodeDead = false;
        }

        this.activeServer = target.label;

        if (this.verbose) {
          const n = decoded.answers?.length || 0;
          console.log(
            `[DNS] ${typeName} ${normalizedName} via ${target.label} → ` +
            `${decoded.rcode}, ${n} answer(s), ${Date.now() - start}ms`
          );
        }

        return response;
      } catch (error) {
        lastError = error;

        if (target.isLocal) {
          this._localNodeDead = true;
          this._localNodeRetryAt = Date.now() + 60_000; // retry in 60s
          console.warn(
            `[DNS] local node failed (${error.message}) — using primary for next 60s`
          );
        }

        if (this.verbose) {
          console.warn(
            `[DNS] ${typeName} ${normalizedName} via ${target.label} FAILED ` +
            `(${Date.now() - start}ms): ${error.message}`
          );
        }
      }
    }

    throw new Error(`All DNS targets failed: ${lastError?.message}`);
  }

  sendQuery(address, port, packet, id, timeout = this.timeout) {
    return new Promise((resolve, reject) => {
      const family = address.includes(':') ? 'udp6' : 'udp4';
      const socket = dgram.createSocket(family);
      const timer = setTimeout(() => {
        socket.close();
        reject(new Error('DNS timeout'));
      }, timeout);

      socket.once('error', error => {
        clearTimeout(timer);
        try { socket.close(); } catch {}
        reject(error);
      });

      socket.once('message', message => {
        clearTimeout(timer);
        try { socket.close(); } catch {}
        resolve(message);
      });

      socket.send(packet, port, address, error => {
        if (error) {
          clearTimeout(timer);
          try { socket.close(); } catch {}
          reject(error);
        }
      });
    });
  }

  async query(name, type = 'A') {
    return dnsPacket.decode(await this.queryWire(name, type));
  }

  async resolveTLSA(domain, port = 443, proto = 'tcp') {
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
    if (!['tcp', 'udp', 'sctp'].includes(proto)) throw new Error('Unsupported transport protocol');

    const label = `_${port}._${proto}`;
    const labels = String(domain).toLowerCase().replace(/\.$/, '').split('.');
    const candidates = [`${label}.${labels.join('.')}`];

    for (let i = 1; i < labels.length; i++) {
      const parent = labels.slice(i).join('.');
      candidates.push(`${label}.*.${parent}`);
      candidates.push(`*.${label}.${parent}`);
    }

    for (const name of candidates) {
      let response;
      try { response = await this.query(name, 'TLSA'); }
      catch { continue; }

      if (response.rcode === 'NXDOMAIN') continue;
      if (response.rcode !== 'NOERROR') continue;

      const tlsa = (response.answers || []).filter(r => r.type === 'TLSA');
      if (tlsa.length) return tlsa.map(r => ({ ...r, lookupName: name }));
    }

    return [];
  }
}
