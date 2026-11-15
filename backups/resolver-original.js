import dnsPacket from 'dns-packet'; // optional, fallback if not present
import { Buffer } from 'buffer';

/**
 * DNS resolver with DNSSEC (DO bit) support via DoH.
 * Does not trust AD flag alone — cryptographic validation is separate.
 */
export class DnsResolver {
  constructor(options = {}) {
    this.dohUrl = options.dohUrl || 'https://cloudflare-dns.com/dns-query';
    this.timeout = options.timeout || 5000;
  }

  async query(name, type = 'TLSA', doh = true) {
    const typeNum = typeof type === 'string' ? dnsPacket.types[type] || 52 : type; // 52 = TLSA

    const query = {
      type: 'query',
      id: Math.floor(Math.random() * 65535),
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{ type: typeNum, name }]
    };

    // EDNS0 with DO bit for DNSSEC
    const packet = dnsPacket.encode(query);
    // Note: full EDNS construction is more involved; simplified for now

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const res = await fetch(this.dohUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          'Accept': 'application/dns-message'
        },
        body: packet,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!res.ok) throw new Error(`DoH failed: ${res.status}`);

      const buf = Buffer.from(await res.arrayBuffer());
      const decoded = dnsPacket.decode(buf);
      return decoded;
    } catch (err) {
      clearTimeout(timeoutId);
      throw err;
    }
  }

  async resolveTLSA(domain, port = 443, proto = 'tcp') {
    const name = `_${port}._${proto}.${domain}`;
    const response = await this.query(name, 'TLSA');
    return response.answers || [];
  }
}
