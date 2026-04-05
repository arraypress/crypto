import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { encrypt, decrypt, sha256, secureCompare, randomToken, deriveKey } from '../src/index.js';

describe('encrypt + decrypt', () => {
  it('round-trips a string', async () => {
    const plaintext = 'sk_live_abc123xyz';
    const encrypted = await encrypt(plaintext, 'my-secret');
    const decrypted = await decrypt(encrypted, 'my-secret');
    assert.equal(decrypted, plaintext);
  });

  it('produces different ciphertext each time (random IV)', async () => {
    const a = await encrypt('hello', 'secret');
    const b = await encrypt('hello', 'secret');
    assert.notEqual(a, b);
  });

  it('fails with wrong secret', async () => {
    const encrypted = await encrypt('hello', 'correct-secret');
    await assert.rejects(() => decrypt(encrypted, 'wrong-secret'));
  });

  it('handles empty string', async () => {
    const encrypted = await encrypt('', 'secret');
    const decrypted = await decrypt(encrypted, 'secret');
    assert.equal(decrypted, '');
  });

  it('handles unicode', async () => {
    const plaintext = 'Hello 世界 🌍';
    const encrypted = await encrypt(plaintext, 'secret');
    const decrypted = await decrypt(encrypted, 'secret');
    assert.equal(decrypted, plaintext);
  });

  it('respects custom salt', async () => {
    const encrypted = await encrypt('hello', 'secret', { salt: 'custom-salt' });
    const decrypted = await decrypt(encrypted, 'secret', { salt: 'custom-salt' });
    assert.equal(decrypted, 'hello');

    // Wrong salt fails
    await assert.rejects(() => decrypt(encrypted, 'secret', { salt: 'different-salt' }));
  });
});

describe('sha256', () => {
  it('hashes a string', async () => {
    const hash = await sha256('hello');
    assert.equal(hash, '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });

  it('produces consistent output', async () => {
    const a = await sha256('test');
    const b = await sha256('test');
    assert.equal(a, b);
  });

  it('produces different output for different input', async () => {
    const a = await sha256('hello');
    const b = await sha256('world');
    assert.notEqual(a, b);
  });
});

describe('secureCompare', () => {
  it('returns true for equal strings', () => {
    assert.equal(secureCompare('abc', 'abc'), true);
  });

  it('returns false for different strings', () => {
    assert.equal(secureCompare('abc', 'def'), false);
  });

  it('returns false for different lengths', () => {
    assert.equal(secureCompare('abc', 'abcd'), false);
  });

  it('returns false for non-strings', () => {
    assert.equal(secureCompare(null, 'abc'), false);
    assert.equal(secureCompare('abc', 123), false);
  });
});

describe('randomToken', () => {
  it('generates a string', () => {
    const token = randomToken();
    assert.equal(typeof token, 'string');
    assert.ok(token.length > 0);
  });

  it('generates unique tokens', () => {
    const a = randomToken();
    const b = randomToken();
    assert.notEqual(a, b);
  });

  it('respects byte length', () => {
    const short = randomToken(8);
    const long = randomToken(64);
    assert.ok(short.length < long.length);
  });

  it('produces base64url characters only', () => {
    const token = randomToken(48);
    assert.match(token, /^[A-Za-z0-9_-]+$/);
  });
});

describe('deriveKey', () => {
  it('returns a CryptoKey', async () => {
    const key = await deriveKey('secret');
    assert.equal(key.type, 'secret');
    assert.equal(key.algorithm.name, 'AES-GCM');
  });
});
