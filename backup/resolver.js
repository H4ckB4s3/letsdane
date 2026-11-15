
import dnsPacket from 'dns-packet';
import { Buffer } from 'node:buffer';
import { randomInt } from 'node:crypto';

const TYPE_MAP = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  DS: 43,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  NSEC3: 50,
  TLSA: 52,
  CDS: 59,
  CDNSKEY: 60
};

export class DnsResolver {
  constructor(options = {}) {
    this.dohUrl =
      options.dohUrl || 'https://cloudflare-dns.com/dns-query';

    this.timeout = options.timeout ?? 5000;
  }

  async queryWire(name, type = 'A') {
    const typeName =
      typeof type === 'string'
        ? type.toUpperCase()
        : Object.keys(TYPE_MAP).find(
            key => TYPE_MAP[key] === type
          );

    if (!typeName || !TYPE_MAP[typeName]) {
      throw new Error(`Unsupported DNS record type: ${type}`);
    }

    const id = randomInt(0, 65536);

    const query = {
      type: 'query',
      id,
      flags:
        dnsPacket.RECURSION_DESIRED |
        dnsPacket.CHECKING_DISABLED,
      questions: [
        {
          type: typeName,
          name: name.endsWith('.') ? name : `${name}.`,
          class: 'IN'
        }
      ],
      additionals: [
        {
          type: 'OPT',
          name: '.',
          udpPayloadSize: 1232,
          flags: dnsPacket.DNSSEC_OK,
          options: []
        }
      ]
    };

    const packet = dnsPacket.encode(query);
    const controller = new AbortController();

    const timeoutId = setTimeout(
      () => controller.abort(),
      this.timeout
    );

    try {
      const response = await fetch(this.dohUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          Accept: 'application/dns-message'
        },
        body: packet,
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`DoH HTTP error: ${response.status}`);
      }

      const contentType =
        response.headers.get('content-type') || '';

      if (!contentType.toLowerCase().includes('application/dns-message')) {
        throw new Error(`Unexpected content type: ${contentType}`);
      }

      const result = Buffer.from(await response.arrayBuffer());

      if (result.length < 12) {
        throw new Error('DNS response too short');
      }

      const decoded = dnsPacket.decode(result);

      if (decoded.id !== id) {
        throw new Error('DNS transaction ID mismatch');
      }

      if (decoded.type !== 'response') {
        throw new Error('Invalid DNS response');
      }

      const expectedName = (
  name.endsWith('.') ? name : `${name}.`
).toLowerCase();

const receivedQuestion = decoded.questions?.[0];

console.log('[DNS DEBUG]', {
  expectedName,
  expectedType: typeName,
  receivedName: receivedQuestion?.name,
  receivedType: receivedQuestion?.type,
  questionCount: decoded.questions?.length
});

if (
  decoded.questions?.length !== 1 ||
  receivedQuestion.type !== typeName ||
  receivedQuestion.name.replace(/\.$/, '').toLowerCase() !==
    expectedName.replace(/\.$/, '')
) {
  throw new Error('DNS question mismatch');
}

      if (decoded.flags & dnsPacket.TRUNCATED_RESPONSE) {
        throw new Error('Truncated DNS response');
      }

      return result;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async query(name, type = 'A') {
    const wire = await this.queryWire(name, type);
    return dnsPacket.decode(wire);
  }

  async resolveTLSA(domain, port = 443, proto = 'tcp') {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error('Invalid port');
    }

    if (!['tcp', 'udp', 'sctp'].includes(proto)) {
      throw new Error('Unsupported transport protocol');
    }

    const name = `_${port}._${proto}.${domain}`;
    const response = await this.query(name, 'TLSA');

    if (response.rcode !== 'NOERROR') {
      throw new Error(`TLSA query failed: ${response.rcode}`);
    }

    return (response.answers || []).filter(
      record => record.type === 'TLSA'
    );
  }
}
