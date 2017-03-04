'use strict'

import { ec as EC } from 'elliptic'
import { createHash } from 'crypto'
import KeyEncoder from 'key-encoder'
import { isHexadecimal } from 'validator'

import { derToJose, joseToDer } from './ecdsaSigFormatter'
import { MissingParametersError } from '../errors'

export class SECP256K1Client {
  constructor() {
  }

  static createHash(signingInput) {
    return createHash('sha256').update(signingInput).digest()
  }

  static loadPrivateKey(rawPrivateKey) {
    if (rawPrivateKey.length === 66) {
      rawPrivateKey = rawPrivateKey.slice(0, 64)
    }
    return SECP256K1Client.ec.keyFromPrivate(rawPrivateKey)
  }

  static loadPublicKey(rawPublicKey) {
    return SECP256K1Client.ec.keyFromPublic(rawPublicKey, 'hex')
  }

  static encodePublicKey(publicKey, originalFormat, destinationFormat) {
    return SECP256K1Client.keyEncoder.encodePublic(
      publicKey, originalFormat, destinationFormat)
  }

  static derivePublicKey(privateKey, compressed) {
    if (typeof privateKey !== 'string') {
      throw Error('private key must be a string')
    }
    if (!isHexadecimal(privateKey)) {
      throw Error('private key must be a hex string')
    }
    if (privateKey.length == 66) {
      privateKey = privateKey.slice(0, 64)
    } else if (privateKey.length <= 64) {
      // do nothing
    } else {
      throw Error('private key must be 66 characters or less')
    }
    if (compressed === undefined) {
      compressed = true
    }
    const keypair = SECP256K1Client.ec.keyFromPrivate(privateKey)
    return keypair.getPublic(compressed, 'hex')
  }

  static signHash(signingInputHash, rawPrivateKey, format='jose') {
    // make sure the required parameters are provided
    if (!(signingInputHash && rawPrivateKey)) {
      throw new MissingParametersError(
        'a signing input hash and private key are all required')
    }
    // prepare the private key
    const privateKeyObject = SECP256K1Client.loadPrivateKey(rawPrivateKey)
    // calculate the signature
    const signatureObject = privateKeyObject.sign(signingInputHash)
    const derSignature = new Buffer(signatureObject.toDER())

    if (format === 'der') {
      return derSignature.toString('hex')
    } else if (format === 'jose') {
      // return the JOSE-formatted signature
      return derToJose(derSignature, 'ES256')
    } else {
      throw Error('Invalid signature format')
    }
  }
  
  static loadSignature(joseSignature) {
    // create and return the DER-formatted signature buffer
    return joseToDer(joseSignature, 'ES256')
  }

  static verifyHash(signingInputHash, derSignatureBuffer, rawPublicKey) {
    // make sure the required parameters are provided
    if (!(signingInputHash && derSignatureBuffer && rawPublicKey)) {
      throw new MissingParametersError(
        'a signing input hash, der signature, and public key are all required')
    }
    // prepare the public key
    const publicKeyObject = SECP256K1Client.loadPublicKey(rawPublicKey)
    // verify the token
    return publicKeyObject.verify(signingInputHash, derSignatureBuffer)
  }
}

SECP256K1Client.algorithmName = 'ES256K'
SECP256K1Client.ec = new EC('secp256k1')
SECP256K1Client.keyEncoder = new KeyEncoder({
    curveParameters: [1, 3, 132, 0, 10],
    privatePEMOptions: {label: 'EC PRIVATE KEY'},
    publicPEMOptions: {label: 'PUBLIC KEY'},
    curve: SECP256K1Client.ec
})