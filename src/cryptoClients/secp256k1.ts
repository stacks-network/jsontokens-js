import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import * as secp from '@noble/secp256k1';
import { derToJose, joseToDer } from 'ecdsa-sig-formatter';
import { MissingParametersError } from '../errors';

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
    return Buffer.from(secp.getPublicKey(privateKey, compressed)).toString('hex');
  }

  static signHash(signingInputHash: string | Buffer, privateKey: string, format = 'jose') {
    // make sure the required parameters are provided
    if (!signingInputHash || !privateKey) {
      throw new MissingParametersError('a signing input hash and private key are all required');
    }

    const derSignature = Buffer.from(
      secp.signSync(signingInputHash, privateKey, { der: true, canonical: false })
    );

    if (format === 'der') return derSignature.toString('hex');
    if (format === 'jose') return derToJose(derSignature, 'ES256');

    throw Error('Invalid signature format');
  }

  static loadSignature(joseSignature: string | Buffer) {
    // create and return the DER-formatted signature buffer
    return joseToDer(joseSignature, 'ES256');
  }

  static verifyHash(
    signingInputHash: Buffer,
    derSignatureBuffer: string | Buffer,
    publicKey: string | Buffer
  ) {
    // make sure the required parameters are provided
    if (!signingInputHash || !derSignatureBuffer || !publicKey) {
      throw new MissingParametersError(
        'a signing input hash, der signature, and public key are all required'
      );
    }

    return secp.verify(derSignatureBuffer, signingInputHash, publicKey, { strict: false });
  }
}
