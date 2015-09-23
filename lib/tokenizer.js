'use strict'

var base64url = require('base64url'),
    decodeToken = require('./decode'),
    CryptoClients = require('./crypto-clients')

function Tokenizer(signingAlgorithm) {
    if (typeof signingAlgorithm !== 'string') {
        throw 'signing algorithm parameter must be a string'
    }
    if (!CryptoClients.hasOwnProperty(signingAlgorithm)) {
        throw 'invalid signing algorithm'
    }
    this.tokenType = 'JWT'
    this.cryptoClient = CryptoClients[signingAlgorithm]
}

Tokenizer.prototype.header = function() {
    return {'typ': this.tokenType, 'alg': this.cryptoClient.algorithmName}
}

Tokenizer.prototype.sign = function(payload, rawPrivateKey) {
    var tokenParts = []

    // add in the header
    var encodedHeader = base64url.encode(JSON.stringify(this.header()))
    tokenParts.push(encodedHeader)

    // add in the payload
    var encodedPayload = base64url.encode(JSON.stringify(payload))
    tokenParts.push(encodedPayload)

    // prepare the message
    var signingInput = tokenParts.join('.'),
        signingInputHash = this.cryptoClient.createHash(signingInput)

    // sign the message and add in the signature
    var signature = this.cryptoClient.signHash(signingInputHash, rawPrivateKey)
    tokenParts.push(signature)

    // return the token
    return tokenParts.join('.')
}

Tokenizer.prototype.decode = function(token) {
    return decodeToken(token)
}

Tokenizer.prototype.verify = function(token, rawPublicKey) {
    // decompose the token into parts
    var tokenParts = token.split('.')

    // calculate the signing input hash
    var signingInput = tokenParts[0] + '.' + tokenParts[1],
        signingInputHash = this.cryptoClient.createHash(signingInput)

    // extract the signature as a DER array
    var derSignatureBuffer = this.cryptoClient.loadSignature(tokenParts[2])
 
    // verify the signed hash
    return this.cryptoClient.verifyHash(signingInputHash, derSignatureBuffer, rawPublicKey)
}

module.exports = Tokenizer