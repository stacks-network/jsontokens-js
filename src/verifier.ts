import base64url from 'base64url'
import { cryptoClients, SECP256K1Client } from './cryptoClients'
import { MissingParametersError } from './errors'
import { SignedToken } from './signer'

export class TokenVerifier {

    tokenType: string
    cryptoClient: typeof SECP256K1Client
    rawPublicKey: string

    constructor(signingAlgorithm: string, rawPublicKey: string) {
        if (!(signingAlgorithm && rawPublicKey)) {
            throw new MissingParametersError(
                'a signing algorithm and public key are required')
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
        this.rawPublicKey = rawPublicKey
    }

    verify(token: string | SignedToken) {
        if (typeof token === 'string') {
            return this.verifyCompact(token)
        } else if (typeof token === 'object') {
            return this.verifyExpanded(token)
        } else {
            return false
        }
    }

    verifyCompact(token: string) {
        // decompose the token into parts
        const tokenParts = token.split('.')

        // calculate the signing input hash
        const signingInput = tokenParts[0] + '.' + tokenParts[1]
        const signingInputHash = this.cryptoClient.createHash(signingInput)

        // extract the signature as a DER array
        const derSignatureBuffer = this.cryptoClient.loadSignature(tokenParts[2])

        // verify the signed hash
        return this.cryptoClient.verifyHash(
            signingInputHash, derSignatureBuffer, this.rawPublicKey)
    }

    verifyExpanded(token: SignedToken) {
        const signingInput = [
            token['header'].join('.'),
            base64url.encode(token['payload'])
        ].join('.')
        const signingInputHash = this.cryptoClient.createHash(signingInput)

        let verified = true

        token['signature'].map((signature: string) => {
            const derSignatureBuffer = this.cryptoClient.loadSignature(signature)
            const signatureVerified = this.cryptoClient.verifyHash(
                signingInputHash, derSignatureBuffer, this.rawPublicKey)
            if (!signatureVerified) {
                verified = false
            }
        })

        return verified
    }
}
