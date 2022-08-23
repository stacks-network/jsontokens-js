import { sha256 } from '@noble/hashes/sha256';

export function hashSha256(input: Uint8Array | string): Uint8Array {
  return sha256(input);
}

export async function hashSha256Async(input: Uint8Array | string): Promise<Uint8Array> {
  try {
    const isSubtleCryptoAvailable =
      typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';
    if (isSubtleCryptoAvailable) {
      // Use the W3C Web Crypto API if available (running in a web browser).
      const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
      const hash = await crypto.subtle.digest('SHA-256', bytes);
      return new Uint8Array(hash);
    } else {
      // Otherwise try loading the Node.js `crypto` module (running in Node.js, or an older browser with a polyfill).
      const nodeCrypto = require('crypto') as typeof import('crypto');
      if (!nodeCrypto.createHash) {
        throw new Error('`crypto` module does not contain `createHash`');
      }
      return Promise.resolve(nodeCrypto.createHash('sha256').update(input).digest());
    }
  } catch (error) {
    console.log(error);
    console.log(
      'Crypto lib not found. Neither the global `crypto.subtle` Web Crypto API, ' +
        'nor the or the Node.js `require("crypto").createHash` module is available. ' +
        'Falling back to JS implementation.'
    );
    return Promise.resolve(hashSha256(input));
  }
}
