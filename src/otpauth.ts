/**
 * CROTP otpauth URI parsing and Base32 decoding (RFC 4648)
 * - Parses otpauth://totp URIs
 * - Extracts label, issuer, secret (Base32), algorithm, digits, period
 * - Normalizes values and returns a structured TOTP entry
 */

import type { TOTPHashAlg } from './totp';
import { normalizeAlg, normalizeDigits, normalizePeriod } from './totp';

export interface ParsedTOTPEntry {
  label: string;
  issuer?: string;
  secretBytes: Uint8Array;
  algorithm: TOTPHashAlg;
  digits: 6 | 8;
  period: number;
}

/**
 * Parse an otpauth URI (Google Authenticator format).
 * Example: otpauth://totp/Issuer:Account?secret=BASE32&issuer=Issuer&algorithm=SHA256&digits=6&period=30
 * Notes:
 * - Only TOTP is supported (HOTP rejected)
 * - Base32 secret may include spaces and '=' padding; both tolerated
 */
export function parseOtpauthUri(uri: string): ParsedTOTPEntry {
  const raw = uri.trim();
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('Invalid otpauth URI: malformed URL');
  }
  if (url.protocol !== 'otpauth:') {
    throw new Error('Invalid otpauth URI: protocol must be otpauth');
  }
  const type = url.hostname.toLowerCase();
  if (type !== 'totp') {
    throw new Error('Only TOTP is supported');
  }

  const labelRaw = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
  const { label, issuerFromLabel } = splitLabel(labelRaw);

  const params = url.searchParams;
  const secretParam = params.get('secret');
  if (!secretParam) {
    throw new Error('Missing secret parameter');
  }

  const algorithmParam = params.get('algorithm') || undefined;
  const digitsParam = params.get('digits');
  const periodParam = params.get('period');
  const issuerParam = params.get('issuer') || undefined;

  const algorithm = normalizeAlg(algorithmParam as any);
  const digits = normalizeDigits(digitsParam ? parseInt(digitsParam, 10) : undefined);
  const period = normalizePeriod(periodParam ? parseInt(periodParam, 10) : undefined);

  const secretBytes = base32DecodeToBytes(secretParam);

  return {
    label,
    issuer: issuerParam || issuerFromLabel || undefined,
    secretBytes,
    algorithm,
    digits,
    period,
  };
}

/**
 * Split "Issuer:Account" label form used by otpauth.
 * Returns cleaned label and optional issuer derived from label.
 */
function splitLabel(labelRaw: string): { label: string; issuerFromLabel?: string } {
  const cleaned = labelRaw.trim();
  const idx = cleaned.indexOf(':');
  if (idx > 0) {
    const issuer = cleaned.slice(0, idx).trim();
    const account = cleaned.slice(idx + 1).trim();
    return { label: account || cleaned, issuerFromLabel: issuer || undefined };
  }
  return { label: cleaned };
}

/**
 * Base32 (RFC 4648) decode to bytes.
 * Accepts upper/lowercase, ignores spaces and '=' padding.
 */
export function base32DecodeToBytes(input: string): Uint8Array {
  const cleaned = input.replace(/\s+/g, '').replace(/=+$/g, '').toUpperCase();
  if (cleaned.length === 0) return new Uint8Array(0);

  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const lookup = new Map<string, number>();
  for (let i = 0; i < alphabet.length; i++) lookup.set(alphabet[i], i);

  let bits = 0;
  let value = 0;
  const out: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i];
    const v = lookup.get(ch);
    if (v === undefined) {
      throw new Error(`Invalid Base32 character: ${ch}`);
    }
    value = (value << 5) | v;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      const byte = (value >>> bits) & 0xff;
      out.push(byte);
    }
  }

  // Any remaining bits < 8 are padding; ignore
  return new Uint8Array(out);
}

/**
 * Convenience helper: Build a ParsedTOTPEntry from manual form fields.
 * Inputs: label, issuer, secret Base32, algorithm, digits, period
 */
export function fromManualInput(
  label: string,
  issuer: string | undefined,
  secretBase32: string,
  algorithmInput: string | undefined,
  digitsInput: number | undefined,
  periodInput: number | undefined
): ParsedTOTPEntry {
  const algorithm = normalizeAlg(algorithmInput as any);
  const digits = normalizeDigits(digitsInput);
  const period = normalizePeriod(periodInput);
  const secretBytes = base32DecodeToBytes(secretBase32);
  return {
    label: label.trim(),
    issuer: issuer?.trim() || undefined,
    secretBytes,
    algorithm,
    digits,
    period,
  };
}