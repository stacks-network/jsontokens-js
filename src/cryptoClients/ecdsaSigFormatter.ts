/*
 * This code is taken from https://github.com/Brightspace/node-ecdsa-sig-formatter
 * which is licensed under the Apache 2.0 license.
 *
 * It got copied over here to make some adjustments for being compatible with browserify.
 * Going forward would be either simplifying this code (as we only need 256 bit signatures),
 * or moving back to the direct dependency; both is future work(TM) for some other day.
 */


'use strict'

const asn1 = require('asn1.js')

function base64UrlEscape(str) {
  return str.replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

const ECDSASigValue = asn1.define('ECDSASigValue', function () {
    this.seq().obj(
        this.key('r').int(),
        this.key('s').int()
    )
})

const seq = 0x10,
      int = 0x02

function getParamSize(keySize) {
    const result = ((keySize / 8) | 0) + (keySize % 8 === 0 ? 0 : 1)
    return result
}

const paramBytesForAlg = {
    ES256: getParamSize(256),
    ES384: getParamSize(384),
    ES512: getParamSize(512)
}

function getParamBytesForAlg(alg) {
    const paramBytes = paramBytesForAlg[alg]
    if (paramBytes) {
        return paramBytes
    }

    throw new Error('Unknown algorithm "' + alg + '"')
}

function bignumToBuf(bn, numBytes) {
    const buf = Buffer.from(bn.toString('hex', numBytes), 'hex')
    return buf
}

function signatureAsBuffer(signature) {
    if (Buffer.isBuffer(signature)) {
        return Buffer.from(signature)
    } else if ('string' === typeof signature) {
        return Buffer.from(signature, 'base64')
    }

    throw new TypeError('ECDSA signature must be a Base64 string or a Buffer')
}

function reduceBuffer(buf) {
    let padding = 0
    for (let n = buf.length; padding < n && buf[padding] === 0;) {
        ++padding
    }

    const needsSign = buf[padding] >= 0x80
    if (needsSign) {
        --padding

        if (padding < 0) {
            const old = buf
            buf = Buffer.alloc(1 + buf.length)
            buf[0] = 0
            old.copy(buf, 1)

            return buf
        }
    }

    if (padding === 0) {
        return buf
    }

    buf = buf.slice(padding)
    return buf
}

export function derToJose(signature, alg) {
    signature = signatureAsBuffer(signature)
    const paramBytes = getParamBytesForAlg(alg)

    signature = ECDSASigValue.decode(signature, 'der')

    const r = bignumToBuf(signature.r, paramBytes)
    const s = bignumToBuf(signature.s, paramBytes)

    signature = Buffer.concat([r, s], r.length + s.length)
    signature = signature.toString('base64')
    signature = base64UrlEscape(signature)

    return signature
}

export function joseToDer(signature, alg) {
    signature = signatureAsBuffer(signature)
    const paramBytes = getParamBytesForAlg(alg)

    const signatureBytes = signature.length
    if (signatureBytes !== paramBytes * 2) {
        throw new TypeError('"' + alg + '" signatures must be "' + paramBytes * 2 + '" bytes, saw "' + signatureBytes + '"')
    }

    const r = reduceBuffer(signature.slice(0, paramBytes))
    const s = reduceBuffer(signature.slice(paramBytes))

    const rsBytes = 1 + 1 + r.length + 1 + 1 + s.length

    const oneByteLength = rsBytes < 0x80

    signature = Buffer.alloc((oneByteLength ? 2 : 3) + rsBytes)

    let offset = 0
    signature[offset++] = (seq | 0x20) | 0 << 6
    if (oneByteLength) {
        signature[offset++] = rsBytes
    } else {
        signature[offset++] = 0x80 | 1
        signature[offset++] = rsBytes & 0xff
    }
    signature[offset++] = int | (0 << 6)
    signature[offset++] = r.length
    r.copy(signature, offset)
    offset += r.length
    signature[offset++] = int | (0 << 6)
    signature[offset++] = s.length
    s.copy(signature, offset)

    return signature
}
