# @arraypress/crypto

AES-256-GCM encryption with PBKDF2 key derivation. Zero dependencies, Web Crypto API.

Uses the Web Crypto API — works in Cloudflare Workers, Node.js 20+, Deno, Bun, and browsers.

## Installation

```bash
npm install @arraypress/crypto
```

## Usage

```js
import { encrypt, decrypt, sha256, secureCompare, randomToken } from '@arraypress/crypto';

// Encrypt and decrypt
const encrypted = await encrypt('sk_live_abc123', 'my-secret');
const decrypted = await decrypt(encrypted, 'my-secret');
// => 'sk_live_abc123'

// Hash
const hash = await sha256('my-session-token');

// Constant-time comparison
const match = secureCompare(apiKey, storedKey);

// Random token
const token = randomToken(); // 43-char base64url string
```

## API

### `encrypt(plaintext, secret, options?)`

Encrypt a string using AES-256-GCM with PBKDF2 key derivation. Returns a base64url-encoded string containing the IV prepended to the ciphertext. The same plaintext encrypted twice produces different outputs (random IV).

```ts
function encrypt(plaintext: string, secret: string, options?: KeyOptions): Promise<string>
```

**Options:**

| Option       | Type     | Description                                            |
| ------------ | -------- | ------------------------------------------------------ |
| `salt`       | `string` | Salt for PBKDF2 (default: `'arraypress-crypto-v1'`).  |
| `iterations` | `number` | PBKDF2 iterations (default: `100000`).                 |

```js
const encrypted = await encrypt('sk_live_abc123', 'my-encryption-secret');

// Custom key derivation
const encrypted = await encrypt('sensitive-data', 'my-secret', {
  salt: 'my-app-salt',
  iterations: 200_000,
});
```

### `decrypt(encrypted, secret, options?)`

Decrypt a base64url-encoded ciphertext produced by `encrypt()`. Options must match those used during encryption.

```ts
function decrypt(encrypted: string, secret: string, options?: KeyOptions): Promise<string>
```

**Options:** Same as `encrypt()`.

```js
const decrypted = await decrypt(encrypted, 'my-encryption-secret');
// => 'sk_live_abc123'
```

Throws an `Error` if decryption fails (wrong key, corrupted data, etc).

### `sha256(input)`

Hash a string using SHA-256. Returns a hex-encoded string.

```ts
function sha256(input: string): Promise<string>
```

```js
const hash = await sha256('my-session-token');
// => 'a1b2c3d4e5f6...'
```

### `secureCompare(a, b)`

Constant-time string comparison to prevent timing attacks. Returns `false` if either argument is not a string or if lengths differ.

```ts
function secureCompare(a: string, b: string): boolean
```

```js
if (secureCompare(providedKey, storedKey)) {
  // Authenticated
}
```

### `randomToken(bytes?)`

Generate a cryptographically random base64url-encoded string.

```ts
function randomToken(bytes?: number): string
```

| Parameter | Type     | Default | Description            |
| --------- | -------- | ------- | ---------------------- |
| `bytes`   | `number` | `32`    | Number of random bytes |

```js
const token = randomToken();    // 32 bytes = 43 chars
const short = randomToken(16);  // 16 bytes = 22 chars
```

### `deriveKey(secret, options?)`

Derive an AES-256 CryptoKey from a secret string using PBKDF2. Used internally by `encrypt()` and `decrypt()`, but exported for advanced use cases.

```ts
function deriveKey(secret: string, options?: KeyOptions): Promise<CryptoKey>
```

**Options:** Same as `encrypt()`.

```js
const key = await deriveKey('my-secret', {
  salt: 'custom-salt',
  iterations: 200_000,
});
```

## License

MIT
