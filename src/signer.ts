import base64url from 'base64url'
import { cryptoClients, SECP256K1Client } from './cryptoClients'
import { MissingParametersError } from './errors'
import { Json } from './decode'
import { hashSha256, hashSha256Async } from './cryptoClients/sha256'

function createSigningInput(payload: Json, header: Json) {
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

export function createUnsecuredToken(payload: Json) {
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
    
    sign(payload: Json): string;
    sign(payload: Json, expanded: true, customHeader?: Json): SignedToken;
    sign(payload: Json, expanded: false, customHeader?: Json): string;
    sign(payload: Json, expanded: boolean = false, customHeader: Json = {}): SignedToken | string {
        // generate the token header
        const header = this.header(customHeader)

        // prepare the message to be signed
        const signingInput = createSigningInput(payload, header)
        const signingInputHash = hashSha256(signingInput)
        return this.createWithSignedHash(payload, expanded, header, signingInput, signingInputHash)
    }

    signAsync(payload: Json): Promise<string>;
    signAsync(payload: Json, expanded: true, customHeader?: Json): Promise<SignedToken>;
    signAsync(payload: Json, expanded: false, customHeader?: Json): Promise<string>;
    async signAsync(payload: Json, expanded: boolean = false, customHeader: Json = {}) {
        // generate the token header
        const header = this.header(customHeader)

        // prepare the message to be signed
        const signingInput = createSigningInput(payload, header)
        const signingInputHash = await hashSha256Async(signingInput)
        return this.createWithSignedHash(payload, expanded, header, signingInput, signingInputHash)
    }

    createWithSignedHash(
        payload: Json, 
        expanded: boolean, 
        header: { typ: string; alg: string }, 
        signingInput: string, 
        signingInputHash: Buffer
    ):
        SignedToken | string {
        // sign the message and add in the signature
        const signature = this.cryptoClient.signHash(
            signingInputHash, this.rawPrivateKey)

        if (expanded) {
            const signedToken: SignedToken = {
                'header': [
                    base64url.encode(JSON.stringify(header))
                ],
                'payload': JSON.stringify(payload),
                'signature': [
                    signature
                ]
            }
            return signedToken
        } else {
            return [signingInput, signature].join('.')
        }
    }
}
