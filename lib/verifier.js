'use strict'

var base64url = require('base64url'),
    CryptoClients = require('./crypto-clients'),
    decodeToken = require('./decode')

function TokenVerifier(signingAlgorithm, rawPublicKey) {
    if (!(signingAlgorithm && rawPublicKey)) {
        throw new MissingParametersError('a signing algorithm and public key are required')
    }
    if (typeof signingAlgorithm !== 'string') {
        throw 'signing algorithm parameter must be a string'
    }
    signingAlgorithm = signingAlgorithm.toUpperCase()
    if (!CryptoClients.hasOwnProperty(signingAlgorithm)) {
        throw 'invalid signing algorithm'
    }
    this.tokenType = 'JWT'
    this.cryptoClient = CryptoClients[signingAlgorithm]
    this.rawPublicKey = rawPublicKey
}

TokenVerifier.prototype.verify = function(token) {
    // decompose the token into parts
    var tokenParts = token.split('.')

    // calculate the signing input hash
    var signingInput = tokenParts[0] + '.' + tokenParts[1],
        signingInputHash = this.cryptoClient.createHash(signingInput)

    // extract the signature as a DER array
    var derSignatureBuffer = this.cryptoClient.loadSignature(tokenParts[2])
 
    // verify the signed hash
    return this.cryptoClient.verifyHash(signingInputHash, derSignatureBuffer, this.rawPublicKey)
}

module.exports = TokenVerifier