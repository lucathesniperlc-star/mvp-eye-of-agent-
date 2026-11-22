import fs from 'node:fs';
import path from 'node:path';

const DEFAULT_DATA_DIR = path.resolve(process.cwd(), '.data');
const DEFAULT_STATE_FILE = path.join(DEFAULT_DATA_DIR, 'eoa-store.json');

export interface PersistedStoreSnapshot {
  version: number;
  savedAt: string;
  data: Record<string, unknown>;
}

export class FileStatePersistence {
  public readonly filePath: string;
  private readonly enabled: boolean;

  constructor(options?: { enabled?: boolean; filePath?: string }) {
    this.enabled = Boolean(options?.enabled);
    this.filePath = options?.filePath || process.env.EOA_STATE_FILE || DEFAULT_STATE_FILE;
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  load(): PersistedStoreSnapshot | null {
    if (!this.enabled) return null;
    try {
      if (!fs.existsSync(this.filePath)) return null;
      const raw = fs.readFileSync(this.filePath, 'utf8');
      if (!raw.trim()) return null;
      const parsed = JSON.parse(raw) as PersistedStoreSnapshot;
      if (!parsed || typeof parsed !== 'object' || !parsed.data) return null;
      return parsed;
    } catch {
      return null;
    }
  }

  save(data: Record<string, unknown>): void {
    if (!this.enabled) return;
    try {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const payload: PersistedStoreSnapshot = {
        version: 1,
        savedAt: new Date().toISOString(),
        data,
      };
      const tmpPath = `${this.filePath}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2, 8)}.tmp`;
      fs.writeFileSync(tmpPath, JSON.stringify(payload), 'utf8');
      fs.renameSync(tmpPath, this.filePath);
    } catch (err) {
      console.error('Failed to persist store snapshot:', err);
    }
  }

  clear(): void {
    if (!this.enabled) return;
    try {
      if (fs.existsSync(this.filePath)) {
        fs.unlinkSync(this.filePath);
      }
    } catch (err) {
      console.error('Failed to clear persisted store snapshot:', err);
    }
  }
}
