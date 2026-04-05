export interface KeyOptions {
  /** Salt string for PBKDF2 (default: 'arraypress-crypto-v1'). */
  salt?: string;
  /** PBKDF2 iterations (default: 100,000). */
  iterations?: number;
}

/** Derive an AES-256 key from a secret using PBKDF2. */
export function deriveKey(secret: string, options?: KeyOptions): Promise<CryptoKey>;

/** Encrypt a string using AES-256-GCM. Returns base64url. */
export function encrypt(plaintext: string, secret: string, options?: KeyOptions): Promise<string>;

/** Decrypt a base64url string encrypted with encrypt(). */
export function decrypt(encrypted: string, secret: string, options?: KeyOptions): Promise<string>;

/** SHA-256 hash a string. Returns hex. */
export function sha256(input: string): Promise<string>;

/** Constant-time string comparison. */
export function secureCompare(a: string, b: string): boolean;

/** Generate a cryptographically random base64url token. */
export function randomToken(bytes?: number): string;
