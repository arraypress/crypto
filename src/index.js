/**
 * @arraypress/crypto
 *
 * AES-256-GCM encryption with PBKDF2 key derivation.
 *
 * Zero dependencies. Uses the Web Crypto API — works in Cloudflare Workers,
 * Node.js 20+, Deno, Bun, and browsers.
 *
 * @module @arraypress/crypto
 */

const ALGORITHM = 'AES-GCM';
const IV_BYTES = 12;
const DEFAULT_ITERATIONS = 100_000;
const DEFAULT_SALT = 'arraypress-crypto-v1';

// ── Encoding Helpers ─────────────────────

function toBase64url(bytes) {
  const bin = String.fromCharCode(...bytes);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64url(str) {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(base64);
  return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
}

// ── Key Derivation ──────────────────────

/**
 * Derive an AES-256 key from a secret string using PBKDF2.
 *
 * @param {string} secret - The secret/password to derive from.
 * @param {Object} [options]
 * @param {string} [options.salt] - Salt string (default: 'arraypress-crypto-v1').
 * @param {number} [options.iterations] - PBKDF2 iterations (default: 100,000).
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKey(secret, options = {}) {
  const salt = new TextEncoder().encode(options.salt || DEFAULT_SALT);
  const iterations = options.iterations || DEFAULT_ITERATIONS;

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: ALGORITHM, length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// ── Encrypt / Decrypt ───────────────────

/**
 * Encrypt a plaintext string using AES-256-GCM.
 *
 * Returns a base64url-encoded string containing the IV prepended to the ciphertext.
 * The same plaintext encrypted twice will produce different outputs (random IV).
 *
 * @param {string} plaintext - The string to encrypt.
 * @param {string} secret - The secret key (passed through PBKDF2).
 * @param {Object} [options]
 * @param {string} [options.salt] - Custom salt for key derivation.
 * @param {number} [options.iterations] - Custom PBKDF2 iterations.
 * @returns {Promise<string>} Base64url-encoded encrypted string.
 *
 * @example
 * const encrypted = await encrypt('sk_live_abc123', 'my-encryption-secret');
 * // => 'dGhpcyBpcyBhIHRl...'
 */
export async function encrypt(plaintext, secret, options = {}) {
  const key = await deriveKey(secret, options);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv },
    key,
    new TextEncoder().encode(plaintext),
  );

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return toBase64url(combined);
}

/**
 * Decrypt a base64url-encoded ciphertext (with prepended IV).
 *
 * @param {string} encrypted - The base64url-encoded encrypted string.
 * @param {string} secret - The same secret used for encryption.
 * @param {Object} [options]
 * @param {string} [options.salt] - Custom salt (must match encryption).
 * @param {number} [options.iterations] - Custom iterations (must match encryption).
 * @returns {Promise<string>} The decrypted plaintext.
 * @throws {Error} If decryption fails (wrong key, corrupted data, etc).
 *
 * @example
 * const decrypted = await decrypt(encrypted, 'my-encryption-secret');
 * // => 'sk_live_abc123'
 */
export async function decrypt(encrypted, secret, options = {}) {
  const key = await deriveKey(secret, options);
  const combined = fromBase64url(encrypted);

  const iv = combined.slice(0, IV_BYTES);
  const ciphertext = combined.slice(IV_BYTES);

  const decrypted = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv },
    key,
    ciphertext,
  );

  return new TextDecoder().decode(decrypted);
}

// ── Hashing ─────────────────────────────

/**
 * Hash a string using SHA-256. Returns a hex string.
 *
 * @param {string} input - The string to hash.
 * @returns {Promise<string>} Hex-encoded SHA-256 hash.
 *
 * @example
 * const hash = await sha256('my-session-token');
 * // => 'a1b2c3d4...'
 */
export async function sha256(input) {
  const data = new TextEncoder().encode(input);
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Constant-time string comparison to prevent timing attacks.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
export function secureCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  if (bufA.length !== bufB.length) return false;
  let result = 0;
  for (let i = 0; i < bufA.length; i++) {
    result |= bufA[i] ^ bufB[i];
  }
  return result === 0;
}

/**
 * Generate a cryptographically random token as a base64url string.
 *
 * @param {number} [bytes=32] - Number of random bytes.
 * @returns {string} Base64url-encoded random string.
 *
 * @example
 * const token = randomToken();    // 32 bytes = 43 chars
 * const short = randomToken(16);  // 16 bytes = 22 chars
 */
export function randomToken(bytes = 32) {
  return toBase64url(crypto.getRandomValues(new Uint8Array(bytes)));
}
