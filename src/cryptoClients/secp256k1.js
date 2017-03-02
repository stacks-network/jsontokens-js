'use strict'

import { ec as EC } from 'elliptic'
import { createHash } from 'crypto'
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

  static privateKeyToPublicKey(rawPrivateKey) {
    if (typeof rawPrivateKey !== 'string') {
      throw 'private key must be a string'
    }
    if (rawPrivateKey.length === 66) {
      rawPrivateKey = rawPrivateKey.slice(0, 64)
    } else if (rawPrivateKey.length === 64) {
      // do nothing
    } else {
      throw 'private key must be a 64 or 66 character hex string'
    }
    const keypair = SECP256K1Client.ec.keyFromPrivate(rawPrivateKey)
    return keypair.getPublic(true, 'hex')
  }

  static signHash(signingInputHash, rawPrivateKey) {
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
    const joseSignature = derToJose(derSignature, 'ES256')
    // return the JOSE-formatted signature
    return joseSignature
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