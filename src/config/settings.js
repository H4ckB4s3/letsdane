import fs from 'node:fs';
import path from 'node:path';
import { isIP } from 'node:net';

const DEFAULT_ICANN_TLDS = [
  'com','net','org','edu','gov','mil','int',
  'io','co','app','dev','info','biz','me',
  'tv','xyz','cloud','site','online','store',
  'shop','tech','blog','news','live','pro',
  'name','mobi','asia','eu','us','uk','de',
  'fr','nl','be','ch','at','se','no','dk',
  'fi','es','it','pt','pl','cz','gr','ru',
  'ca','au','nz','jp','cn','in','br','mx'
];

const DEFAULT_RESOLVER_PROFILE = { label: 'Handshake resolver', ip: '82.68.70.162' };

const DEFAULTS = {
  activeResolver: DEFAULT_RESOLVER_PROFILE.ip,
  resolverProfiles: [DEFAULT_RESOLVER_PROFILE],
  useSecondary: false,
  secondary: '',
  timeout: 5000,
  useLocalNode: false,
  localNodeAddress: '127.0.0.1',
  localNodePort: 5350,
  icannTlds: DEFAULT_ICANN_TLDS
};

function normalizeTld(value) {
  const tld = String(value || '').trim().toLowerCase().replace(/^\./, '').replace(/\.$/, '');
  if (!tld || tld.length > 63 || tld.includes('.') ||
      !/^[a-z0-9-]+$/.test(tld) || tld.startsWith('-') || tld.endsWith('-')) {
    throw new Error(`Invalid TLD: ${value}`);
  }
  return tld;
}

function normalizeProfile(p) {
  const label = String(p.label || '').trim();
  const ip = String(p.ip || '').trim();
  if (!label) throw new Error('Resolver profile needs a label');
  if (isIP(ip) !== 4 && isIP(ip) !== 6) {
    throw new Error(`Resolver profile ${label}: invalid IP ${ip}`);
  }
  return { label, ip };
}

export class SettingsStore {
  constructor(file = 'data/settings.json') {
    this.file = path.resolve(file);
    this.settings = this.load();
  }

  validate(input) {
    // Resolver profiles
    if (!Array.isArray(input.resolverProfiles) || !input.resolverProfiles.length) {
      throw new Error('At least one resolver profile is required');
    }
    const profiles = input.resolverProfiles.map(normalizeProfile);

    // The default must always be present and selectable
    const hasDefault = profiles.some(p => p.ip === DEFAULT_RESOLVER_PROFILE.ip);
    if (!hasDefault) profiles.unshift({ ...DEFAULT_RESOLVER_PROFILE });

    // Active resolver must exist in profiles (or fall back to default)
    const active = String(input.activeResolver || '').trim();
    const activeExists = profiles.some(p => p.ip === active);
    const activeResolver = activeExists ? active : profiles[0].ip;

    // Secondary
    const secondary = String(input.secondary || '').trim();
    if (input.useSecondary && isIP(secondary) !== 4 && isIP(secondary) !== 6) {
      throw new Error('Secondary resolver must be a valid IPv4 or IPv6 address');
    }

    // Local node
    const localAddr = String(input.localNodeAddress || '127.0.0.1').trim();
    if (isIP(localAddr) !== 4 && isIP(localAddr) !== 6) {
      throw new Error('Local node address must be IPv4 or IPv6');
    }
    const localPort = Number(input.localNodePort);
    if (!Number.isInteger(localPort) || localPort < 1 || localPort > 65535) {
      throw new Error('Local node port must be 1–65535');
    }

    // TLDs
    if (!Array.isArray(input.icannTlds)) throw new Error('icannTlds must be an array');
    const icannTlds = [...new Set(input.icannTlds.map(normalizeTld))].sort();

    return {
      activeResolver,
      resolverProfiles: profiles,
      useSecondary: input.useSecondary === true,
      secondary,
      timeout: 5000,
      useLocalNode: input.useLocalNode === true,
      localNodeAddress: localAddr,
      localNodePort: localPort,
      icannTlds
    };
  }

  load() {
    if (!fs.existsSync(this.file)) return this.save(DEFAULTS);
    const saved = JSON.parse(fs.readFileSync(this.file, 'utf8'));

    // Migration: old shape → new shape
    const migrated = { ...DEFAULTS, ...saved };

    // Old primary field becomes the active resolver + default profile
    if (saved.primary && !saved.resolverProfiles) {
      migrated.resolverProfiles = [
        DEFAULT_RESOLVER_PROFILE,
        { label: 'Custom', ip: saved.primary }
      ].filter((p, i, arr) => arr.findIndex(q => q.ip === p.ip) === i);
      migrated.activeResolver = saved.primary;
    }

    if (!Array.isArray(migrated.icannTlds) || !migrated.icannTlds.length) {
      migrated.icannTlds = DEFAULT_ICANN_TLDS;
    }

    return this.validate(migrated);
  }

  get() {
    return {
      ...this.settings,
      resolverProfiles: this.settings.resolverProfiles.map(p => ({ ...p })),
      icannTlds: [...this.settings.icannTlds]
    };
  }

  save(input) {
    const next = this.validate({ ...this.settings, ...input });
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(next, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
    this.settings = next;
    return this.get();
  }
}
