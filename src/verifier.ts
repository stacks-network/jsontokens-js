import base64url from 'base64url'
import { cryptoClients, SECP256K1Client } from './cryptoClients'
import { MissingParametersError } from './errors'
import { SignedToken } from './signer'
import { hashSha256Async, hashSha256 } from './cryptoClients/sha256'

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

    verify(token: string | SignedToken): boolean {
        if (typeof token === 'string') {
            return this.verifyCompact(token, false)
        } else if (typeof token === 'object') {
            return this.verifyExpanded(token, false)
        } else {
            false
        }
    }

    verifyAsync(token: string | SignedToken): Promise<boolean> {
        if (typeof token === 'string') {
            return this.verifyCompact(token, true)
        } else if (typeof token === 'object') {
            return this.verifyExpanded(token, true)
        } else {
            return Promise.resolve(false)
        }
    }

    verifyCompact(token: string, async: false): boolean
    verifyCompact(token: string, async: true): Promise<boolean>
    verifyCompact(token: string, async: boolean): boolean | Promise<boolean> {
        // decompose the token into parts
        const tokenParts = token.split('.')

        // calculate the signing input hash
        const signingInput = tokenParts[0] + '.' + tokenParts[1]

        const performVerify = (signingInputHash: Buffer) => {
            // extract the signature as a DER array
            const derSignatureBuffer = this.cryptoClient.loadSignature(tokenParts[2])

            // verify the signed hash
            return this.cryptoClient.verifyHash(
                signingInputHash, derSignatureBuffer, this.rawPublicKey)
        }

        if (async) {
            return hashSha256Async(signingInput).then(signingInputHash => 
                performVerify(signingInputHash))
        } else {
            const signingInputHash = hashSha256(signingInput)
            return performVerify(signingInputHash)
        }
    }

    verifyExpanded(token: SignedToken, async: false): boolean;
    verifyExpanded(token: SignedToken, async: true): Promise<boolean>;
    verifyExpanded(token: SignedToken, async: boolean): boolean | Promise<boolean> {
        const signingInput = [
            token['header'].join('.'),
            base64url.encode(token['payload'])
        ].join('.')
        let verified = true

        const performVerify = (signingInputHash: Buffer) => {
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

        if (async) {
            return hashSha256Async(signingInput).then(signingInputHash => 
                performVerify(signingInputHash))
        } else {
            const signingInputHash = hashSha256(signingInput)
            return performVerify(signingInputHash)
        }
    }
}
