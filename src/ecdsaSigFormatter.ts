//  NOTICE
//  Copyright 2015 D2L Corporation
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

// The following code is adapted from https://github.com/Brightspace/node-ecdsa-sig-formatter

import { fromByteArray, toByteArray, byteLength } from 'base64-js';

function getParamSize(keySize: number): number {
  return ((keySize / 8) | 0) + (keySize % 8 === 0 ? 0 : 1);
}

export type Alg = 'ES256' | 'ES384' | 'ES512';

const paramBytesForAlg = {
  ES256: getParamSize(256),
  ES384: getParamSize(384),
  ES512: getParamSize(521),
} as Record<Alg, number>;

function getParamBytesForAlg(alg: Alg): number {
  const paramBytes = paramBytesForAlg[alg];
  if (paramBytes) {
    return paramBytes;
  }

  throw new Error(`Unknown algorithm "${alg}"`);
}

const MAX_OCTET = 0x80;
const CLASS_UNIVERSAL = 0;
const PRIMITIVE_BIT = 0x20;
const TAG_SEQ = 0x10;
const TAG_INT = 0x02;
const ENCODED_TAG_SEQ = TAG_SEQ | PRIMITIVE_BIT | (CLASS_UNIVERSAL << 6);
const ENCODED_TAG_INT = TAG_INT | (CLASS_UNIVERSAL << 6);

function base64Url(base64: string): string {
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64Pad(base64: string): string {
  return `${base64}${'='.repeat(base64.length % 3)}`;
}

function signatureAsBytes(signature: string | Uint8Array) {
  if (signature instanceof Uint8Array) {
    return signature;
  } else if ('string' === typeof signature) {
    return toByteArray(base64Pad(signature));
  }

  throw new TypeError('ECDSA signature must be a Base64 string or a Uint8Array');
}

export function derToJose(signature: string | Uint8Array, alg: Alg) {
  const signatureBytes = signatureAsBytes(signature);
  const paramBytes = getParamBytesForAlg(alg);

  // the DER encoded param should at most be the param size, plus a padding
  // zero, since due to being a signed integer
  const maxEncodedParamLength = paramBytes + 1;

  const inputLength = signatureBytes.length;

  let offset = 0;
  if (signatureBytes[offset++] !== ENCODED_TAG_SEQ) {
    throw new Error('Could not find expected "seq"');
  }

  let seqLength = signatureBytes[offset++];
  if (seqLength === (MAX_OCTET | 1)) {
    seqLength = signatureBytes[offset++];
  }

  if (inputLength - offset < seqLength) {
    throw new Error(
      `"seq" specified length of "${seqLength}", only "${inputLength - offset}" remaining`
    );
  }

  if (signatureBytes[offset++] !== ENCODED_TAG_INT) {
    throw new Error('Could not find expected "int" for "r"');
  }

  const rLength = signatureBytes[offset++];

  if (inputLength - offset - 2 < rLength) {
    throw new Error(
      `"r" specified length of "${rLength}", only "${inputLength - offset - 2}" available`
    );
  }

  if (maxEncodedParamLength < rLength) {
    throw new Error(
      `"r" specified length of "${rLength}", max of "${maxEncodedParamLength}" is acceptable`
    );
  }

  const rOffset = offset;
  offset += rLength;

  if (signatureBytes[offset++] !== ENCODED_TAG_INT) {
    throw new Error('Could not find expected "int" for "s"');
  }

  const sLength = signatureBytes[offset++];

  if (inputLength - offset !== sLength) {
    throw new Error(`"s" specified length of "${sLength}", expected "${inputLength - offset}"`);
  }

  if (maxEncodedParamLength < sLength) {
    throw new Error(
      `"s" specified length of "${sLength}", max of "${maxEncodedParamLength}" is acceptable`
    );
  }

  const sOffset = offset;
  offset += sLength;

  if (offset !== inputLength) {
    throw new Error(`Expected to consume entire array, but "${inputLength - offset}" bytes remain`);
  }

  const rPadding = paramBytes - rLength;
  const sPadding = paramBytes - sLength;

  const dst = new Uint8Array(rPadding + rLength + sPadding + sLength);

  for (offset = 0; offset < rPadding; ++offset) {
    dst[offset] = 0;
  }
  dst.set(signatureBytes.subarray(rOffset + Math.max(-rPadding, 0), rOffset + rLength), offset);

  offset = paramBytes;

  for (const o = offset; offset < o + sPadding; ++offset) {
    dst[offset] = 0;
  }
  dst.set(signatureBytes.subarray(sOffset + Math.max(-sPadding, 0), sOffset + sLength), offset);

  return base64Url(fromByteArray(dst));
}

function countPadding(buf: Uint8Array, start: number, stop: number) {
  let padding = 0;
  while (start + padding < stop && buf[start + padding] === 0) {
    ++padding;
  }

  const needsSign = buf[start + padding] >= MAX_OCTET;
  if (needsSign) {
    --padding;
  }

  return padding;
}

export function joseToDer(signature: string | Uint8Array, alg: Alg) {
  signature = signatureAsBytes(signature);
  const paramBytes = getParamBytesForAlg(alg);

  const signatureBytes = signature.length;
  if (signatureBytes !== paramBytes * 2) {
    throw new TypeError(
      `"${alg}" signatures must be "${paramBytes * 2}" bytes, saw "${signatureBytes}"`
    );
  }

  const rPadding = countPadding(signature, 0, paramBytes);
  const sPadding = countPadding(signature, paramBytes, signature.length);
  const rLength = paramBytes - rPadding;
  const sLength = paramBytes - sPadding;

  const rsBytes = 1 + 1 + rLength + 1 + 1 + sLength;

  const shortLength = rsBytes < MAX_OCTET;

  const dst = new Uint8Array((shortLength ? 2 : 3) + rsBytes);

  let offset = 0;
  dst[offset++] = ENCODED_TAG_SEQ;
  if (shortLength) {
    // Bit 8 has value "0"
    // bits 7-1 give the length.
    dst[offset++] = rsBytes;
  } else {
    // Bit 8 of first octet has value "1"
    // bits 7-1 give the number of additional length octets.
    dst[offset++] = MAX_OCTET | 1;
    // length, base 256
    dst[offset++] = rsBytes & 0xff;
  }
  dst[offset++] = ENCODED_TAG_INT;
  dst[offset++] = rLength;
  if (rPadding < 0) {
    dst[offset++] = 0;
    dst.set(signature.subarray(0, paramBytes), offset);
    offset += paramBytes;
  } else {
    dst.set(signature.subarray(rPadding, paramBytes), offset);
    offset += paramBytes - rPadding;
  }
  dst[offset++] = ENCODED_TAG_INT;
  dst[offset++] = sLength;
  if (sPadding < 0) {
    dst[offset++] = 0;
    dst.set(signature.subarray(paramBytes), offset);
  } else {
    dst.set(signature.subarray(paramBytes + sPadding), offset);
  }

  return dst;
}
