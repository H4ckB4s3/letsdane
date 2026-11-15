import fs from 'node:fs';
import path from 'node:path';
import { isIP } from 'node:net';

const DEFAULTS = {
  primary: '82.68.70.162',
  secondary: '82.68.70.163',
  useSecondary: true,
  timeout: 5000
};

export class SettingsStore {
  constructor(file = 'data/settings.json') {
    this.file = path.resolve(file);
    this.settings = this.load();
  }

  validate(input) {
    const primary = String(input.primary || '').trim();
    const secondary = String(input.secondary || '').trim();

    if (isIP(primary) !== 4) {
      throw new Error('Primary resolver must be a valid IPv4 address');
    }

    if (input.useSecondary && isIP(secondary) !== 4) {
      throw new Error('Secondary resolver must be a valid IPv4 address');
    }

    return {
      primary,
      secondary,
      useSecondary: input.useSecondary === true,
      timeout: 5000
    };
  }

  load() {
    try {
      const saved = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      return this.validate({ ...DEFAULTS, ...saved });
    } catch {
      this.save(DEFAULTS);
      return { ...DEFAULTS };
    }
  }

  get() {
    return { ...this.settings };
  }

  save(input) {
    const next = this.validate({ ...DEFAULTS, ...input });

    fs.mkdirSync(path.dirname(this.file), { recursive: true });

    const temporary = `${this.file}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(next, null, 2), {
      mode: 0o600
    });
    fs.renameSync(temporary, this.file);

    this.settings = next;
    return this.get();
  }
}
