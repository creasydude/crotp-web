/**
 * CROTP TOTP core (RFC 6238)
 * - Computes previous, current, next codes
 * - Supports SHA-1 (default) and SHA-256
 * - Supports 6 or 8 digits (default 6)
 * - Pure WebCrypto (no external deps)
 */

export type TOTPHashAlg = 'SHA-1' | 'SHA-256';
export type TOTPAlgInput = 'SHA-1' | 'SHA1' | 'SHA-256' | 'SHA256';

export interface TOTPOptions {
  /**
   * Shared secret (binary). Convert from Base32 before calling (see otpauth.ts).
   */
  secret: Uint8Array;
  /**
   * Time step duration in seconds. Default 30.
   */
  period?: number;
  /**
   * Number of digits in OTP (6 or 8). Default 6.
   */
  digits?: 6 | 8;
  /**
   * Hash algorithm. Default 'SHA-1'.
   */
  algorithm?: TOTPAlgInput;
  /**
   * Timestamp (ms since epoch). Default Date.now().
   */
  timestamp?: number;
}

export interface TOTPWindow {
  /**
   * Previous time step code
   */
  prev: string;
  /**
   * Current time step code
   */
  current: string;
  /**
   * Next time step code
   */
  next: string;
  /**
   * Seconds remaining in current time step
   */
  remainingSeconds: number;
  /**
   * Current step index (floor(timestamp / period))
   */
  step: number;
  /**
   * Period used for generation
   */
  period: number;
  /**
   * Digits used for generation
   */
  digits: 6 | 8;
  /**
   * Algorithm used for generation
   */
  algorithm: TOTPHashAlg;
}

/**
 * Normalize algorithm input to WebCrypto-compatible values.
 */
export function normalizeAlg(alg?: TOTPAlgInput): TOTPHashAlg {
  if (!alg) return 'SHA-1';
  const up = alg.toUpperCase();
  if (up === 'SHA1' || up === 'SHA-1') return 'SHA-1';
  if (up === 'SHA256' || up === 'SHA-256') return 'SHA-256';
  // Fallback to SHA-1 for widest compatibility
  return 'SHA-1';
}

/**
 * Normalize digits to 6 or 8. Default 6.
 */
export function normalizeDigits(d?: number): 6 | 8 {
  return d === 8 ? 8 : 6;
}

/**
 * Normalize period (seconds). Default 30s. Minimum 5s, maximum 300s (sane bounds).
 */
export function normalizePeriod(p?: number): number {
  const period = typeof p === 'number' && Number.isFinite(p) ? Math.floor(p) : 30;
  return Math.min(300, Math.max(5, period));
}

/**
 * Compute the current step index from timestamp and period.
 */
export function stepAt(timestampMs: number, period: number): number {
  const seconds = Math.floor(timestampMs / 1000);
  return Math.floor(seconds / period);
}

/**
 * Compute seconds remaining in the current time step.
 */
export function secondsRemaining(timestampMs: number, period: number): number {
  const seconds = Math.floor(timestampMs / 1000);
  return period - (seconds % period) - 1; // show 0..(period-1) as UX remainder
}

/**
 * Convert a number (step) to 8-byte big-endian array as per HOTP.
 */
export function numberTo8ByteBE(n: number): Uint8Array {
  // Use BigInt to safely handle large step values
  let v = BigInt(Math.floor(n));
  const bytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

/**
 * HMAC(sign) using WebCrypto SubtleCrypto.
 */
async function hmac(bytesKey: Uint8Array, data: Uint8Array, alg: TOTPHashAlg): Promise<Uint8Array> {
  // Convert Uint8Array views to plain ArrayBuffer to satisfy BufferSource typing
  const toBuffer = (view: Uint8Array): ArrayBuffer => {
    const buf = new ArrayBuffer(view.byteLength);
    new Uint8Array(buf).set(view);
    return buf;
  };

  const keyBuffer = toBuffer(bytesKey);
  const dataBuffer = toBuffer(data);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: { name: alg } },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, dataBuffer);
  return new Uint8Array(signature);
}

/**
 * Dynamic truncation as per RFC 4226 (HOTP), section 5.3.
 */
export function dynamicTruncate(hmacBytes: Uint8Array): number {
  const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
  const p = hmacBytes.subarray(offset, offset + 4);
  // 31-bit binary code
  const binCode = ((p[0] & 0x7f) << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
  return binCode;
}

/**
 * Pad a number to N digits with leading zeros.
 */
export function padDigits(n: number, digits: 6 | 8): string {
  const mod = digits === 8 ? 100000000 : 1000000;
  const code = n % mod;
  return code.toString().padStart(digits, '0');
}

/**
 * Generate a single TOTP code for a given step.
 */
export async function generateTOTPForStep(
  secret: Uint8Array,
  step: number,
  digits: 6 | 8 = 6,
  algorithm: TOTPHashAlg = 'SHA-1'
): Promise<string> {
  const moving = numberTo8ByteBE(step);
  const mac = await hmac(secret, moving, algorithm);
  const binCode = dynamicTruncate(mac);
  return padDigits(binCode, digits);
}

/**
 * Generate TOTP code for a given timestamp with configured period.
 */
export async function generateTOTP(opts: TOTPOptions): Promise<string> {
  const period = normalizePeriod(opts.period);
  const digits = normalizeDigits(opts.digits);
  const alg = normalizeAlg(opts.algorithm);
  const ts = typeof opts.timestamp === 'number' ? opts.timestamp : Date.now();
  const step = stepAt(ts, period);
  return generateTOTPForStep(opts.secret, step, digits, alg);
}

/**
 * Generate previous, current, next TOTP codes and timing metadata.
 */
export async function generateTOTPWindow(opts: TOTPOptions): Promise<TOTPWindow> {
  const period = normalizePeriod(opts.period);
  const digits = normalizeDigits(opts.digits);
  const alg = normalizeAlg(opts.algorithm);
  const ts = typeof opts.timestamp === 'number' ? opts.timestamp : Date.now();
  const step = stepAt(ts, period);

  const [prev, current, next] = await Promise.all([
    generateTOTPForStep(opts.secret, step - 1, digits, alg),
    generateTOTPForStep(opts.secret, step, digits, alg),
    generateTOTPForStep(opts.secret, step + 1, digits, alg),
  ]);

  return {
    prev,
    current,
    next,
    remainingSeconds: secondsRemaining(ts, period),
    step,
    period,
    digits,
    algorithm: alg,
  };
}

/**
 * Format a numeric code string into groups for readability.
 * - 6 digits: 3-3
 * - 8 digits: 4-4
 */
export function formatCodeGroupings(code: string): string {
  if (code.length === 6) {
    return `${code.slice(0, 3)} ${code.slice(3)}`;
  }
  if (code.length === 8) {
    return `${code.slice(0, 4)} ${code.slice(4)}`;
  }
  return code;
}