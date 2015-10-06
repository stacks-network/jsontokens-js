'use strict'

var EC = require('elliptic').ec,
    sigFormatter = require('ecdsa-sig-formatter'),
    crypto = require('crypto'),
    MissingParametersError = require('../errors').MissingParametersError

function ES256kClient() {
}

ES256kClient.algorithmName = 'ES256'

var ec = new EC('secp256k1')

ES256kClient.createHash = function(signingInput) {
    return crypto.createHash('sha256').update(signingInput).digest()
}

ES256kClient.loadPrivateKey = function(rawPrivateKey) {
    if (rawPrivateKey.length === 66) {
        rawPrivateKey = rawPrivateKey.slice(0, 64)
    }
    return ec.keyFromPrivate(rawPrivateKey)
}

ES256kClient.loadPublicKey = function(rawPublicKey) {
    return ec.keyFromPublic(rawPublicKey, 'hex')
}

ES256kClient.privateKeyToPublicKey = function(rawPrivateKey) {
    var keypair = ec.keyFromPrivate(rawPrivateKey)
    return keypair.getPublic(true, 'hex')
}

ES256kClient.signHash = function(signingInputHash, rawPrivateKey) {
    // make sure the required parameters are provided
    if (!(signingInputHash && rawPrivateKey)) {
        throw new MissingParametersError('a signing input hash and private key are all required')
    }
    // prepare the private key
    var privateKeyObject = ES256kClient.loadPrivateKey(rawPrivateKey)
    // calculate the signature
    var signatureObject = privateKeyObject.sign(signingInputHash),
        derSignature = new Buffer(signatureObject.toDER()),
        joseSignature = sigFormatter.derToJose(derSignature, 'ES256')
    // return the JOSE-formatted signature
    return joseSignature
}

ES256kClient.loadSignature = function(joseSignature) {
    // create and return the DER-formatted signature buffer
    return sigFormatter.joseToDer(joseSignature, 'ES256')
}

ES256kClient.verifyHash = function(signingInputHash, derSignatureBuffer, rawPublicKey) {
    // make sure the required parameters are provided
    if (!(signingInputHash && derSignatureBuffer && rawPublicKey)) {
        throw new MissingParametersError('a signing input hash, der signature, and public key are all required')
    }
    // prepare the public key
    var publicKeyObject = ES256kClient.loadPublicKey(rawPublicKey)
    // verify the token
    return publicKeyObject.verify(signingInputHash, derSignatureBuffer)
}

module.exports = ES256kClient