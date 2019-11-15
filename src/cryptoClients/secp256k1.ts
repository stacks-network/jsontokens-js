import { ec as EC, BNInput } from 'elliptic'
import { derToJose, joseToDer } from 'ecdsa-sig-formatter'
import { MissingParametersError } from '../errors'

export class SECP256K1Client {

  static ec = new EC('secp256k1')
  static algorithmName = 'ES256K'

  constructor() {
  }

  static loadPrivateKey(rawPrivateKey: string) {
    if (rawPrivateKey.length === 66) {
      rawPrivateKey = rawPrivateKey.slice(0, 64)
    }
    return SECP256K1Client.ec.keyFromPrivate(rawPrivateKey)
  }

  static loadPublicKey(rawPublicKey: string | Buffer) {
    return SECP256K1Client.ec.keyFromPublic(rawPublicKey, 'hex')
  }

  static derivePublicKey(privateKey: string, compressed = true) {
    if (typeof privateKey !== 'string') {
      throw Error('private key must be a string')
    }
    if (!(/^[0-9A-F]+$/i.test(privateKey))) {
      throw Error('private key must be a hex string')
    }
    if (privateKey.length == 66) {
      privateKey = privateKey.slice(0, 64)
    } else if (privateKey.length <= 64) {
      // do nothing
    } else {
      throw Error('private key must be 66 characters or less')
    }
    const keypair = SECP256K1Client.ec.keyFromPrivate(privateKey)
    return keypair.getPublic(compressed, 'hex')
  }

  static signHash(signingInputHash: string | Buffer, rawPrivateKey: string, format = 'jose') {
    // make sure the required parameters are provided
    if (!(signingInputHash && rawPrivateKey)) {
      throw new MissingParametersError(
        'a signing input hash and private key are all required')
    }
    // prepare the private key
    const privateKeyObject = SECP256K1Client.loadPrivateKey(rawPrivateKey)
    // calculate the signature
    const signatureObject = privateKeyObject.sign(signingInputHash)
    const derSignature = Buffer.from(signatureObject.toDER())

    if (format === 'der') {
      return derSignature.toString('hex')
    } else if (format === 'jose') {
      // return the JOSE-formatted signature
      return derToJose(derSignature, 'ES256')
    } else {
      throw Error('Invalid signature format')
    }
  }

  static loadSignature(joseSignature: string | Buffer) {
    // create and return the DER-formatted signature buffer
    return joseToDer(joseSignature, 'ES256')
  }

  static verifyHash(signingInputHash: BNInput, derSignatureBuffer: string | Buffer, rawPublicKey: string | Buffer) {
    // make sure the required parameters are provided
    if (!(signingInputHash && derSignatureBuffer && rawPublicKey)) {
      throw new MissingParametersError(
        'a signing input hash, der signature, and public key are all required')
    }
    // prepare the public key
    const publicKeyObject = SECP256K1Client.loadPublicKey(rawPublicKey)
    // verify the token
    return publicKeyObject.verify(signingInputHash, derSignatureBuffer as any)
  }
}

