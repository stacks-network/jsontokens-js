import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import * as secp from '@noble/secp256k1';
import { derToJose, joseToDer } from '../ecdsaSigFormatter';
import { MissingParametersError } from '../errors';
import { bytesToHex } from '@noble/hashes/utils';

// required to use noble secp https://github.com/paulmillr/noble-secp256k1
secp.utils.hmacSha256Sync = (key: Uint8Array, ...msgs: Uint8Array[]) => {
  const h = hmac.create(sha256, key);
  msgs.forEach(msg => h.update(msg));
  return h.digest();
};

export class SECP256K1Client {
  static algorithmName = 'ES256K';

  static derivePublicKey(privateKey: string, compressed = true): string {
    if (privateKey.length === 66) {
      privateKey = privateKey.slice(0, 64);
    }
    if (privateKey.length < 64) {
      // backward compatibly accept too short private keys
      privateKey = privateKey.padStart(64, '0');
    }
    return bytesToHex(secp.getPublicKey(privateKey, compressed));
  }

  static signHash(signingInputHash: string | Uint8Array, privateKey: string, format = 'jose') {
    // make sure the required parameters are provided
    if (!signingInputHash || !privateKey) {
      throw new MissingParametersError('a signing input hash and private key are all required');
    }

    const derSignature = secp.signSync(signingInputHash, privateKey.slice(0, 64), {
      der: true,
      canonical: false,
    });

    if (format === 'der') return bytesToHex(derSignature);
    if (format === 'jose') return derToJose(derSignature, 'ES256');

    throw Error('Invalid signature format');
  }

  static loadSignature(joseSignature: string | Uint8Array) {
    // create and return the DER-formatted signature bytes
    return joseToDer(joseSignature, 'ES256');
  }

  static verifyHash(
    signingInputHash: Uint8Array,
    derSignatureBytes: string | Uint8Array,
    publicKey: string | Uint8Array
  ) {
    // make sure the required parameters are provided
    if (!signingInputHash || !derSignatureBytes || !publicKey) {
      throw new MissingParametersError(
        'a signing input hash, der signature, and public key are all required'
      );
    }

    return secp.verify(derSignatureBytes, signingInputHash, publicKey, { strict: false });
  }
}
