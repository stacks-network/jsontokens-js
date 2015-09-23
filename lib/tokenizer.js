'use strict'

var base64url = require('base64url'),
    sigFormatter = require('ecdsa-sig-formatter'),
    EC = require('elliptic').ec,
    crypto = require('crypto')

var curves = {
    secp256k1: {
        signingAlgorithm: 'ES256',
        curve: new EC('secp256k1')
    }
}

function assert(val, msg) {
    if (!val) {
        throw new Error(msg || 'Assertion failed')
    }
}

function Tokenizer(options) {
    if (typeof options === 'string') {
        assert(curves.hasOwnProperty(options), 'Unknown curve ' + options)
        options = curves[options]
    }
    this.tokenType = 'JWT'
    this.signingAlgorithm = options.signingAlgorithm
    this.curve = options.curve
}

Tokenizer.prototype.header = function() {
    return {'typ': this.tokenType, 'alg': this.signingAlgorithm}
}

Tokenizer.prototype.sign = function(payload, rawPrivateKey) {
    var tokenParts = []

    // add in the header
    tokenParts.push(base64url.encode(JSON.stringify(this.header())))

    // add in the payload
    tokenParts.push(base64url.encode(JSON.stringify(payload)))

    // prepare the private key
    if (rawPrivateKey.length === 66) {
        rawPrivateKey = rawPrivateKey.slice(0, 64)
    }
    var privateKeyObject = this.curve.keyFromPrivate(rawPrivateKey)

    // prepare the message
    var signingInput = tokenParts.join('.'),
        signingInputHash = crypto.createHash('sha256').update(signingInput).digest()

    // sign the message
    var signatureObject = privateKeyObject.sign(signingInputHash),
        derSignature = new Buffer(signatureObject.toDER()),
        joseSignature = sigFormatter.derToJose(derSignature, 'ES256')

    // add in the signature
    tokenParts.push(joseSignature)

    // return the token
    return tokenParts.join('.')
}

Tokenizer.prototype.decode = function(token) {
    // decompose the token into parts
    var tokenParts = token.split('.'),
        header = JSON.parse(base64url.decode(tokenParts[0])),
        payload = JSON.parse(base64url.decode(tokenParts[1])),
        signature = tokenParts[2]

    // return the token object
    return {
        header: header,
        payload: payload,
        signature: signature
    }
}

Tokenizer.prototype.verify = function(token, rawPublicKey) {
    // decompose the token into parts
    var tokenParts = token.split('.')

    // calculate the signing input hash
    var signingInput = tokenParts[0] + '.' + tokenParts[1],
        signingInputHash = crypto.createHash('sha256').update(signingInput).digest()

    // extract the signature as a DER array
    var joseSignature = tokenParts[2],
        derSignatureBuffer = sigFormatter.joseToDer(joseSignature, 'ES256'),
        derSignatureArray = derSignatureBuffer.toJSON().data
 
    // prepare the public key
    var publicKeyObject = this.curve.keyFromPublic(rawPublicKey, 'hex')

    // verify the token
    var verified = publicKeyObject.verify(signingInputHash, derSignatureArray)

    return verified
}

module.exports = Tokenizer