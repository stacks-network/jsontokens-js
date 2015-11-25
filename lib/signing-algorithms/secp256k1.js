'use strict'

var EC = require('elliptic').ec,
    sigFormatter = require('ecdsa-sig-formatter'),
    crypto = require('crypto'),
    MissingParametersError = require('../errors').MissingParametersError

function SECP256K1Client() {
}

SECP256K1Client.algorithmName = 'ES256K'

var ec = new EC('secp256k1')

SECP256K1Client.createHash = function(signingInput) {
    return crypto.createHash('sha256').update(signingInput).digest()
}

SECP256K1Client.loadPrivateKey = function(rawPrivateKey) {
    if (rawPrivateKey.length === 66) {
        rawPrivateKey = rawPrivateKey.slice(0, 64)
    }
    return ec.keyFromPrivate(rawPrivateKey)
}

SECP256K1Client.loadPublicKey = function(rawPublicKey) {
    return ec.keyFromPublic(rawPublicKey, 'hex')
}

SECP256K1Client.privateKeyToPublicKey = function(rawPrivateKey) {
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
    var keypair = ec.keyFromPrivate(rawPrivateKey)
    return keypair.getPublic(true, 'hex')
}

SECP256K1Client.signHash = function(signingInputHash, rawPrivateKey) {
    // make sure the required parameters are provided
    if (!(signingInputHash && rawPrivateKey)) {
        throw new MissingParametersError('a signing input hash and private key are all required')
    }
    // prepare the private key
    var privateKeyObject = SECP256K1Client.loadPrivateKey(rawPrivateKey)
    // calculate the signature
    var signatureObject = privateKeyObject.sign(signingInputHash),
        derSignature = new Buffer(signatureObject.toDER()),
        joseSignature = sigFormatter.derToJose(derSignature, 'ES256')
    // return the JOSE-formatted signature
    return joseSignature
}

SECP256K1Client.loadSignature = function(joseSignature) {
    // create and return the DER-formatted signature buffer
    return sigFormatter.joseToDer(joseSignature, 'ES256')
}

SECP256K1Client.verifyHash = function(signingInputHash, derSignatureBuffer, rawPublicKey) {
    // make sure the required parameters are provided
    if (!(signingInputHash && derSignatureBuffer && rawPublicKey)) {
        throw new MissingParametersError('a signing input hash, der signature, and public key are all required')
    }
    // prepare the public key
    var publicKeyObject = SECP256K1Client.loadPublicKey(rawPublicKey)
    // verify the token
    return publicKeyObject.verify(signingInputHash, derSignatureBuffer)
}

module.exports = SECP256K1Client