import { sha256 } from 'sha.js'

export function hashSha256(input: Buffer | string): Buffer {
    const hashFunction = new sha256()
    return hashFunction.update(input).digest()
}

export async function hashSha256Async(input: Buffer | string): Promise<Buffer> {
    try {
        const isSubtleCryptoAvailable = typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined'
        if (isSubtleCryptoAvailable) {
            // Use the W3C Web Crypto API if available (running in a web browser).
            const buffer = typeof input === 'string' ? Buffer.from(input) : input
            const hash = await crypto.subtle.digest('SHA-256', buffer)
            return Buffer.from(hash)
        } else {
            // Otherwise try loading the Node.js `crypto` module (running in Node.js, or an older browser with a polyfill).
            const nodeCrypto = require('crypto') as typeof import('crypto')
            if (!nodeCrypto.createHash) {
                throw new Error('`crypto` module does not contain `createHash`')
            }
            return Promise.resolve(nodeCrypto.createHash('sha256').update(input).digest())
        }
    } catch (error) {
        console.log(error)
        console.log(
            'Crypto lib not found. Neither the global `crypto.subtle` Web Crypto API, ' +
            'nor the or the Node.js `require("crypto").createHash` module is available. ' +
            'Falling back to JS implementation.')
        return Promise.resolve(hashSha256(input))
    }
}

