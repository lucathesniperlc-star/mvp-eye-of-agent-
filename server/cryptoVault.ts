import crypto from 'node:crypto';
import type { EncryptedCredentialRecord } from './types';

// Master key used to derive tenant-isolated data encryption keys (DEKs) via HKDF
const ROOT_KEY_MATERIAL =
  process.env.EOA_KMS_MASTER_KEY ||
  'eyes-of-agent-dev-kms-master-key-material-32bytes!';

function deriveTenantKey(tenantId: string, keyId: string): Buffer {
  const derived = crypto.hkdfSync(
    'sha256',
    Buffer.from(ROOT_KEY_MATERIAL, 'utf8'),
    Buffer.from(tenantId, 'utf8'),
    Buffer.from(`eoa-dek:${keyId}`, 'utf8'),
    32
  );
  return Buffer.from(derived);
}

export function encryptTenantSecret(
  tenantId: string,
  connectorId: string,
  plaintextSecret: string,
  tokenVersion = 1
): EncryptedCredentialRecord {
  const keyId = `kms-${tenantId}-v1`;
  const key = deriveTenantKey(tenantId, keyId);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(`${tenantId}:${connectorId}`, 'utf8'));

  const encrypted = Buffer.concat([
    cipher.update(plaintextSecret, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return {
    id: `cred_${crypto.randomUUID()}`,
    tenantId,
    connectorId,
    ciphertextHex: encrypted.toString('hex'),
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
    keyId,
    tokenVersion,
    expiresAt: new Date(Date.now() + 3600 * 1000 * 24 * 30).toISOString(),
    revoked: false,
  };
}

export function decryptTenantSecret(
  tenantId: string,
  record: EncryptedCredentialRecord
): string {
  if (record.tenantId !== tenantId) {
    throw new Error('Cross-tenant credential decryption blocked');
  }
  if (record.revoked) {
    throw new Error('Credential has been revoked');
  }
  const key = deriveTenantKey(tenantId, record.keyId);
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(record.ivHex, 'hex')
  );
  decipher.setAAD(Buffer.from(`${tenantId}:${record.connectorId}`, 'utf8'));
  decipher.setAuthTag(Buffer.from(record.authTagHex, 'hex'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(record.ciphertextHex, 'hex')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

export function createPkcePair(): { codeVerifier: string; codeChallenge: string } {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  return { codeVerifier, codeChallenge };
}

export function verifyPkceChallenge(codeVerifier: string, expectedChallenge: string): boolean {
  const actual = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expectedChallenge));
}

export function redactSensitiveFields<T extends Record<string, unknown>>(obj: T): T {
  const clone: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (/(token|secret|password|ciphertext|authorization|rawPrompt)/i.test(k)) {
      clone[k] = '[REDACTED]';
    } else if (v && typeof v === 'object' && !Array.isArray(v)) {
      clone[k] = redactSensitiveFields(v as Record<string, unknown>);
    } else {
      clone[k] = v;
    }
  }
  return clone as T;
}
