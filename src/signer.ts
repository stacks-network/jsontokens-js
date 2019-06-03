import base64url from 'base64url'
import { cryptoClients, SECP256K1Client } from './cryptoClients'
import { MissingParametersError } from './errors'

function createSigningInput(payload: any, header: any) {
    const tokenParts = []

    // add in the header
    const encodedHeader = base64url.encode(JSON.stringify(header))
    tokenParts.push(encodedHeader)

    // add in the payload
    const encodedPayload = base64url.encode(JSON.stringify(payload))
    tokenParts.push(encodedPayload)

    // prepare the message
    const signingInput = tokenParts.join('.')

    // return the signing input
    return signingInput
}

export function createUnsecuredToken(payload: any) {
    const header = {typ: 'JWT', alg: 'none'}
    return createSigningInput(payload, header) + '.'
}

export interface SignedToken {
    header: string[];
    payload: string;
    signature: string[];
}

export class TokenSigner {
    tokenType: string
    cryptoClient: typeof SECP256K1Client
    rawPrivateKey: string

    constructor(signingAlgorithm: string, rawPrivateKey: string) {
        if (!(signingAlgorithm && rawPrivateKey)) {
            throw new MissingParametersError(
                'a signing algorithm and private key are required')
        }
        if (typeof signingAlgorithm !== 'string') {
            throw new Error('signing algorithm parameter must be a string')
        }
        signingAlgorithm = signingAlgorithm.toUpperCase()
        if (!cryptoClients.hasOwnProperty(signingAlgorithm)) {
            throw new Error('invalid signing algorithm')
        }
        this.tokenType = 'JWT'
        this.cryptoClient = cryptoClients[signingAlgorithm]
        this.rawPrivateKey = rawPrivateKey
    }

    header(header = {}) {
        const defaultHeader = { typ: this.tokenType,
                                alg: this.cryptoClient.algorithmName }
        return Object.assign({}, defaultHeader, header)
    }

    sign(payload: any): string;
    sign(payload: any, expanded: undefined): string;
    sign(payload: any, expanded: false, customHeader?: any): string;
    sign(payload: any, expanded: true, customHeader?: any): SignedToken;
    sign(payload: any, expanded: boolean = false, customHeader: any = {}): string | SignedToken {
        // generate the token header
        const header = this.header(customHeader)

        // prepare the message to be signed
        const signingInput = createSigningInput(payload, header)
        const signingInputHash = this.cryptoClient.createHash(signingInput)

        // sign the message and add in the signature
        const signature = this.cryptoClient.signHash(
            signingInputHash, this.rawPrivateKey)

        if (expanded) {
            return {
                'header': [
                    base64url.encode(JSON.stringify(header))
                ],
                'payload': JSON.stringify(payload),
                'signature': [
                    signature
                ]
            }
        } else {
            return [signingInput, signature].join('.')
        }
    }
}
