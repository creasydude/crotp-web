/**
 * CROTP IndexedDB storage
 * - Database "crotp" with stores: "secrets" and "meta"
 * - Secrets: id, label, issuer, alg, digits, period, encSecret, iv, timestamps, order
 * - Meta: key-value records (salt, schemaVersion, etc.)
 * - All data persists offline; nothing is sent to any server
 */

import type { TOTPHashAlg } from './totp';

export const DB_NAME = 'crotp';
export const DB_VERSION = 1;
export const STORE_SECRETS = 'secrets';
export const STORE_META = 'meta';

export interface DBSecretRecord {
  id: string;
  label: string;
  issuer?: string;
  alg: TOTPHashAlg;
  digits: 6 | 8;
  period: number;
  encSecret: ArrayBuffer; // AES-GCM ciphertext
  iv: ArrayBuffer;        // AES-GCM IV
  createdAt: number;
  updatedAt: number;
  order: number;
}

/**
 * Utility: Convert Uint8Array view to standalone ArrayBuffer (for IDB/WebCrypto).
 */
export function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(view.byteLength);
  new Uint8Array(buf).set(view);
  return buf;
}

/**
 * Utility: Convert ArrayBuffer to Uint8Array.
 */
export function toBytes(buf: ArrayBuffer): Uint8Array {
  return new Uint8Array(buf);
}

/**
 * Promisify IDBRequest into a Promise.
 */
function requestToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result as unknown as T);
    request.onerror = () => reject(request.error);
  });
}

/**
 * Open or create the CROTP database and ensure stores exist.
 */
export async function openDB(): Promise<IDBDatabase> {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;

      // Create secrets store
      if (!db.objectStoreNames.contains(STORE_SECRETS)) {
        const secrets = db.createObjectStore(STORE_SECRETS, { keyPath: 'id' });
        secrets.createIndex('order', 'order', { unique: false });
        secrets.createIndex('label', 'label', { unique: false });
        secrets.createIndex('issuer', 'issuer', { unique: false });
      }

      // Create meta store
      if (!db.objectStoreNames.contains(STORE_META)) {
        db.createObjectStore(STORE_META, { keyPath: 'key' });
      }

      // Initialize schemaVersion meta record
      const tx = (req.transaction as IDBTransaction | null);
      try {
        tx?.objectStore(STORE_META).put({ key: 'schemaVersion', value: 1 });
      } catch {
        // ignore if not available yet
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Meta key-value helpers
 */
export async function metaGet<T = unknown>(key: string): Promise<T | undefined> {
  const db = await openDB();
  const store = db.transaction(STORE_META, 'readonly').objectStore(STORE_META);
  const rec = await requestToPromise<any>(store.get(key));
  return rec?.value as T | undefined;
}

export async function metaPut<T = unknown>(key: string, value: T): Promise<void> {
  const db = await openDB();
  const store = db.transaction(STORE_META, 'readwrite').objectStore(STORE_META);
  await new Promise<void>((resolve, reject) => {
    const req = store.put({ key, value });
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

/**
 * Application salt (PBKDF2). Creates a new salt if missing.
 */
export async function getOrCreateSalt(bytes: number = 16): Promise<Uint8Array> {
  const existing = await metaGet<ArrayBuffer>('salt');
  if (existing) return toBytes(existing);
  const salt = new Uint8Array(bytes);
  crypto.getRandomValues(salt);
  await metaPut('salt', toArrayBuffer(salt));
  return salt;
}

/**
 * Generate a stable random ID (hex) for secret records.
 */
export function generateId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * List all secrets ordered by "order" ascending.
 */
export async function listSecrets(): Promise<DBSecretRecord[]> {
  const db = await openDB();
  const store = db.transaction(STORE_SECRETS, 'readonly').objectStore(STORE_SECRETS);
  const arr = await new Promise<DBSecretRecord[]>((resolve, reject) => {
    const req = store.getAll();
    req.onsuccess = () => resolve((req.result || []) as DBSecretRecord[]);
    req.onerror = () => reject(req.error);
  });
  return arr.slice().sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
}

/**
 * Get a single secret by ID.
 */
export async function getSecret(id: string): Promise<DBSecretRecord | undefined> {
  const db = await openDB();
  const store = db.transaction(STORE_SECRETS, 'readonly').objectStore(STORE_SECRETS);
  const rec = await requestToPromise<any>(store.get(id));
  return rec as DBSecretRecord | undefined;
}

export interface NewSecretInput {
  label: string;
  issuer?: string;
  alg: TOTPHashAlg;
  digits: 6 | 8;
  period: number;
  encSecret: Uint8Array;
  iv: Uint8Array;
}

/**
 * Add a new encrypted secret record. Returns the stored record.
 */
export async function addSecret(input: NewSecretInput): Promise<DBSecretRecord> {
  const db = await openDB();
  const now = Date.now();
  const current = await listSecrets();
  const nextOrder = current.length ? Math.max(...current.map((s) => s.order ?? 0)) + 1 : 1;

  const record: DBSecretRecord = {
    id: generateId(),
    label: input.label.trim(),
    issuer: input.issuer?.trim() || undefined,
    alg: input.alg,
    digits: input.digits,
    period: input.period,
    encSecret: toArrayBuffer(input.encSecret),
    iv: toArrayBuffer(input.iv),
    createdAt: now,
    updatedAt: now,
    order: nextOrder,
  };

  await new Promise<void>((resolve, reject) => {
    const store = db.transaction(STORE_SECRETS, 'readwrite').objectStore(STORE_SECRETS);
    const req = store.add(record);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });

  return record;
}

export interface UpdateSecretInput {
  id: string;
  label?: string;
  issuer?: string;
  alg?: TOTPHashAlg;
  digits?: 6 | 8;
  period?: number;
  encSecret?: Uint8Array;
  iv?: Uint8Array;
  order?: number;
}

/**
 * Update a secret record's metadata and (optionally) encrypted secret.
 */
export async function updateSecret(input: UpdateSecretInput): Promise<DBSecretRecord> {
  const db = await openDB();

  // Load existing
  const existing = await getSecret(input.id);
  if (!existing) throw new Error('Secret not found');

  const updated: DBSecretRecord = {
    ...existing,
    label: input.label !== undefined ? input.label.trim() : existing.label,
    issuer: input.issuer !== undefined ? (input.issuer?.trim() || undefined) : existing.issuer,
    alg: input.alg ?? existing.alg,
    digits: input.digits ?? existing.digits,
    period: input.period ?? existing.period,
    encSecret: input.encSecret ? toArrayBuffer(input.encSecret) : existing.encSecret,
    iv: input.iv ? toArrayBuffer(input.iv) : existing.iv,
    order: input.order ?? existing.order,
    updatedAt: Date.now(),
  };

  await new Promise<void>((resolve, reject) => {
    const store = db.transaction(STORE_SECRETS, 'readwrite').objectStore(STORE_SECRETS);
    const req = store.put(updated);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });

  return updated;
}

/**
 * Delete a secret record by ID.
 */
export async function deleteSecret(id: string): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const store = db.transaction(STORE_SECRETS, 'readwrite').objectStore(STORE_SECRETS);
    const req = store.delete(id);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

/**
 * Apply a new ordering to multiple records.
 */
export async function reorderSecrets(newOrder: { id: string; order: number }[]): Promise<void> {
  if (!newOrder.length) return;
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_SECRETS, 'readwrite');
    const store = tx.objectStore(STORE_SECRETS);

    let remaining = newOrder.length;
    for (const { id, order } of newOrder) {
      const getReq = store.get(id);
      getReq.onsuccess = () => {
        const rec = getReq.result as DBSecretRecord | undefined;
        if (rec) {
          rec.order = order;
          rec.updatedAt = Date.now();
          const putReq = store.put(rec);
          putReq.onsuccess = () => {
            if (--remaining === 0) resolve();
          };
          putReq.onerror = () => reject(putReq.error);
        } else {
          if (--remaining === 0) resolve();
        }
      };
      getReq.onerror = () => reject(getReq.error);
    }
  });
}

/**
 * Danger: Clear all data (for dev/testing/reset UX only).
 */
export async function clearAll(): Promise<void> {
  const db = await openDB();
  await Promise.all([
    new Promise<void>((resolve, reject) => {
      const req = db.transaction(STORE_SECRETS, 'readwrite').objectStore(STORE_SECRETS).clear();
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    }),
    new Promise<void>((resolve, reject) => {
      const req = db.transaction(STORE_META, 'readwrite').objectStore(STORE_META).clear();
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    }),
  ]);
}