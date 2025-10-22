/**
 * CROTP cryptography module
 * - Passphrase-based key derivation: PBKDF2-SHA-256 -> AES-GCM 256-bit
 * - AES-GCM encrypt/decrypt with per-entry IV
 * - Utilities: salt/IV generation, timing-safe compare, zeroization
 * - No external dependencies
 */

export const PBKDF2_ITERATIONS = 200_000; // balance security and performance for web
export const SALT_BYTES = 16;
export const IV_BYTES = 12;

/**
 * Generate a cryptographically secure random byte array.
 */
export function randomBytes(len: number): Uint8Array {
  const out = new Uint8Array(len);
  crypto.getRandomValues(out);
  return out;
}

/**
 * Generate a new salt for PBKDF2.
 */
export function generateSalt(bytes: number = SALT_BYTES): Uint8Array {
  return randomBytes(bytes);
}

/**
 * Zeroize sensitive buffers in-place.
 */
export function zeroize(...views: (Uint8Array | undefined | null)[]): void {
  for (const v of views) {
    if (v) v.fill(0);
  }
}

/**
 * Timing-safe constant-time comparison for byte arrays.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Convert a Uint8Array view to a standalone ArrayBuffer (avoids SAB typing issues).
 */
function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(view.byteLength);
  new Uint8Array(buf).set(view);
  return buf;
}

/**
 * Derive an AES-GCM CryptoKey from a passphrase using PBKDF2-SHA-256.
 * - The returned key is non-extractable.
 */
export async function deriveAesGcmKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const passBytes = enc.encode(passphrase);
  try {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(passBytes),
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    );

    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: toArrayBuffer(salt),
        iterations,
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  } finally {
    zeroize(passBytes);
  }
}

/**
 * Encrypt plaintext with AES-GCM using a fresh random IV.
 * Returns ciphertext and IV.
 */
export async function encryptAESGCM(
  key: CryptoKey,
  plaintext: Uint8Array
): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
  const iv = randomBytes(IV_BYTES);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(plaintext)
  );
  return { ciphertext: new Uint8Array(ct), iv };
}

/**
 * Decrypt ciphertext with AES-GCM using the provided IV.
 */
export async function decryptAESGCM(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(ciphertext)
  );
  return new Uint8Array(pt);
}