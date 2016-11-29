'use strict'

import base64url from 'base64url'
import { cryptoClients } from './cryptoClients'
import decodeToken from './decode'

export class TokenSigner {
    constructor(signingAlgorithm, rawPrivateKey) {
        if (!(signingAlgorithm && rawPrivateKey)) {
            throw new MissingParametersError(
                'a signing algorithm and private key are required')
        }
        if (typeof signingAlgorithm !== 'string') {
            throw 'signing algorithm parameter must be a string'
        }
        signingAlgorithm = signingAlgorithm.toUpperCase()
        if (!cryptoClients.hasOwnProperty(signingAlgorithm)) {
            throw 'invalid signing algorithm'
        }
        this.tokenType = 'JWT'
        this.cryptoClient = cryptoClients[signingAlgorithm]
        this.rawPrivateKey = rawPrivateKey
    }

    header() {
        return {typ: this.tokenType, alg: this.cryptoClient.algorithmName}
    }

    sign(payload) {
        let tokenParts = []

        // add in the header
        const encodedHeader = base64url.encode(JSON.stringify(this.header()))
        tokenParts.push(encodedHeader)

        // add in the payload
        const encodedPayload = base64url.encode(JSON.stringify(payload))
        tokenParts.push(encodedPayload)

        // prepare the message
        const signingInput = tokenParts.join('.')
        const signingInputHash = this.cryptoClient.createHash(signingInput)

        // sign the message and add in the signature
        const signature = this.cryptoClient.signHash(signingInputHash, this.rawPrivateKey)
        tokenParts.push(signature)

        // return the token
        return tokenParts.join('.')
    }
}
