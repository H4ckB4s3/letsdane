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
    this.primary = options.primary || '82.68.70.162';
    this.secondary = options.secondary || '82.68.70.163';
    this.useSecondary = options.useSecondary ?? true;
    this.timeout = options.timeout ?? 5000;
    this.port = options.port ?? 53;
    this.activeServer = null;
  }

  get servers() {
    return [
      this.primary,
      ...(this.useSecondary && this.secondary
        ? [this.secondary]
        : [])
    ];
  }

  async queryWire(name, type = 'A') {
    const typeName = typeof type === 'string'
      ? type.toUpperCase()
      : Object.keys(TYPE_MAP).find(k => TYPE_MAP[k] === type);

    if (!typeName || !TYPE_MAP[typeName]) {
      throw new Error(`Unsupported DNS type: ${type}`);
    }

    const normalizedName = name.endsWith('.') ? name : `${name}.`;
    const id = randomInt(0, 65536);

    const packet = dnsPacket.encode({
      type: 'query',
      id,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{
        type: typeName,
        name: normalizedName,
        class: 'IN'
      }],
      additionals: [{
        type: 'OPT',
        name: '.',
        udpPayloadSize: 1232,
        flags: dnsPacket.DNSSEC_OK,
        options: []
      }]
    });

    let lastError;

    for (const server of this.servers) {
      try {
        const response = await this.sendQuery(server, packet, id);
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

        this.activeServer = server;
        return response;
      } catch (error) {
        lastError = error;
        console.warn(`[DNS] ${server} failed: ${error.message}`);
      }
    }

    throw new Error(`All DNS resolvers failed: ${lastError?.message}`);
  }

  sendQuery(server, packet, id) {
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket('udp4');
      const timer = setTimeout(() => {
        socket.close();
        reject(new Error('DNS timeout'));
      }, this.timeout);

      socket.once('error', error => {
        clearTimeout(timer);
        socket.close();
        reject(error);
      });

      socket.once('message', message => {
        clearTimeout(timer);
        socket.close();
        resolve(message);
      });

      socket.send(packet, this.port, server, error => {
        if (error) {
          clearTimeout(timer);
          socket.close();
          reject(error);
        }
      });
    });
  }

  async query(name, type = 'A') {
    return dnsPacket.decode(await this.queryWire(name, type));
  }

  /**
   * RFC 7671 §2.2.3 lookup order for TLSA:
   *   1. _<port>._<proto>.<host>
   *   2. *._<port>._<proto>.<parent>          (wildcard owner)
   *   3. _<port>._<proto>.*.<parent>          (HNS SLD wildcard)
   *   4. *._<port>._<proto>.*.<parent>
   *
   * If the exact owner exists but is empty, wildcard MUST NOT be used.
   */
  async resolveTLSA(domain, port = 443, proto = 'tcp') {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error('Invalid port');
    }
    if (!['tcp', 'udp', 'sctp'].includes(proto)) {
      throw new Error('Unsupported transport protocol');
    }

    const label = `_${port}._${proto}`;
    const labels = String(domain)
      .toLowerCase()
      .replace(/\.$/, '')
      .split('.');

    const candidates = [`${label}.${labels.join('.')}`];

    // Walk up the tree adding wildcard forms for each ancestor.
    // This catches HNS SLD wildcards like _443._tcp.*.tld
    // as well as standard RFC 7671 wildcards like *._443._tcp.sld.tld
    for (let i = 1; i < labels.length; i++) {
      const parent = labels.slice(i).join('.');
      candidates.push(`${label}.*.${parent}`);
      candidates.push(`*.${label}.${parent}`);
    }

    let sawExact = false;

    for (const name of candidates) {
      let response;
      try {
        response = await this.query(name, 'TLSA');
      } catch (err) {
        console.warn(`[DNS] TLSA ${name} error: ${err.message}`);
        continue;
      }

      if (response.rcode === 'NXDOMAIN') {
        if (name === candidates[0]) sawExact = false;
        continue;
      }

      if (response.rcode !== 'NOERROR') {
        continue;
      }

      const tlsa = (response.answers || []).filter(
        r => r.type === 'TLSA'
      );

      if (name === candidates[0]) {
        sawExact = true;
        if (tlsa.length) {
          return tlsa.map(r => ({ ...r, lookupName: name }));
        }
        // Exact exists but no TLSA — RFC says do NOT fall to wildcard.
        continue;
      }

      if (tlsa.length) {
        return tlsa.map(r => ({ ...r, lookupName: name }));
      }
    }

    if (sawExact) {
      // Exact exists with no TLSA records — treat as "no DANE".
      return [];
    }

    return [];
  }
}
