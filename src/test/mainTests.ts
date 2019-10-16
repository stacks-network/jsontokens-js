import base64url from 'base64url'

import {
    TokenSigner, TokenVerifier, decodeToken, createUnsecuredToken, MissingParametersError
} from '../index'

import * as webcrypto from '@peculiar/webcrypto'

describe('main tests - node.js crypto', () => {
    runMainTests()
})

describe('main tests - web crypto', () => {
    beforeAll(() => {
        Object.defineProperty(global, 'crypto', { value: new webcrypto.Crypto() })
    })
    afterAll(() => {
        delete (global as any)['crypto']
    })
    runMainTests()
})

function runMainTests() {
    const rawPrivateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
    const rawPublicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
    const sampleToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3N1ZWRBdCI6IjE0NDA3MTM0MTQuODUiLCJjaGFsbGVuZ2UiOiI3Y2Q5ZWQ1ZS1iYjBlLTQ5ZWEtYTMyMy1mMjhiZGUzYTA1NDkiLCJpc3N1ZXIiOnsicHVibGljS2V5IjoiMDNmZGQ1N2FkZWMzZDQzOGVhMjM3ZmU0NmIzM2VlMWUwMTZlZGE2YjU4NWMzZTI3ZWE2NjY4NmMyZWE1MzU4NDc5IiwiY2hhaW5QYXRoIjoiYmQ2Mjg4NWVjM2YwZTM4MzgwNDMxMTVmNGNlMjVlZWRkMjJjYzg2NzExODAzZmIwYzE5NjAxZWVlZjE4NWUzOSIsInB1YmxpY0tleWNoYWluIjoieHB1YjY2MU15TXdBcVJiY0ZRVnJRcjRRNGtQamFQNEpqV2FmMzlmQlZLalBkSzZvR0JheUU0NkdBbUt6bzVVRFBRZExTTTlEdWZaaVA4ZWF1eTU2WE51SGljQnlTdlpwN0o1d3N5UVZwaTJheHpaIiwiYmxvY2tjaGFpbmlkIjoicnlhbiJ9fQ.DUf6Rnw6FBKv4Q3y95RX7rR6HG_L1Va96ThcIYTycOf1j_bf9WleLsOyiZ-35Qfw7FgDnW7Utvz4sNjdWOSnhQ'
    const sampleDecodedToken = {
          header: { typ: 'JWT', alg: 'ES256K' },
          payload:
           { issuedAt: '1440713414.85',
             challenge: '7cd9ed5e-bb0e-49ea-a323-f28bde3a0549',
             issuer:
              { publicKey: '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479',
                chainPath: 'bd62885ec3f0e3838043115f4ce25eedd22cc86711803fb0c19601eeef185e39',
                publicKeychain: 'xpub661MyMwAqRbcFQVrQr4Q4kPjaP4JjWaf39fBVKjPdK6oGBayE46GAmKzo5UDPQdLSM9DufZiP8eauy56XNuHicBySvZp7J5wsyQVpi2axzZ',
                blockchainid: 'ryan' } },
          signature: 'oO7ROPKq3T3X0azAXzHsf6ub6CYy5nUUFDoy8MS22B3TlYisqsBrRtzWIQcSYiFXLytrXwAdt6vjehj3OFioDQ'
        }

    test('TokenSigner', async () => {
        const tokenSigner = new TokenSigner('ES256K', rawPrivateKey)
        expect(tokenSigner).toBeTruthy()

        const token = await tokenSigner.sign(sampleDecodedToken.payload)
        expect(token).toBeTruthy()
        expect(typeof token).toBe('string')
        expect(token.split('.').length).toBe(3)

        const decodedToken = decodeToken(token)
        expect(JSON.stringify(decodedToken.header)).toBe(JSON.stringify(sampleDecodedToken.header))
        expect(() => new TokenSigner('ES256K', undefined)).toThrowError(MissingParametersError)
    })


    test('TokenSigner custom header', async () => {
        const tokenSigner = new TokenSigner('ES256K', rawPrivateKey)
        expect(tokenSigner).toBeTruthy()

        const token = await tokenSigner.sign(sampleDecodedToken.payload, undefined, { test: 'TestHeader' })
        expect(token).toBeTruthy()
        expect(typeof token).toBe('string')
        expect(token.split('.').length).toBe(3)

        const decodedToken = decodeToken(token)
        expect(JSON.stringify(decodedToken.header)).toBe(JSON.stringify(Object.assign({},
            sampleDecodedToken.header,
            { test: 'TestHeader' })))
        
        expect(JSON.stringify(decodedToken.payload)).toBe(JSON.stringify(sampleDecodedToken.payload))
        expect(() => new TokenSigner('ES256K', undefined)).toThrowError(MissingParametersError)
    })

    test('createUnsecuredToken', async () => {
        const unsecuredToken = createUnsecuredToken(
            sampleDecodedToken.payload)
        expect(unsecuredToken).toBeTruthy()
        expect(unsecuredToken)
            .toBe(base64url.encode(JSON.stringify({typ: 'JWT', alg: 'none'})) + '.' + sampleToken.split('.')[1] + '.')

        const decodedToken = decodeToken(unsecuredToken)
        expect(decodedToken).toBeTruthy()
    })

    test('TokenVerifier', async () => {
        const tokenVerifier = new TokenVerifier('ES256K', rawPublicKey)
        expect(tokenVerifier).toBeTruthy()

        const verified = await tokenVerifier.verify(sampleToken)
        expect(verified).toBe(true)

        const tokenSigner = new TokenSigner('ES256K', rawPrivateKey)
        const newToken = await tokenSigner.sign(sampleDecodedToken.payload)
        expect(newToken).toBeTruthy()
        const newTokenVerified = await tokenVerifier.verify(newToken)
        expect(newTokenVerified).toBe(true)
    })

    test('decodeToken', () => {
        const decodedToken = decodeToken(sampleToken)
        expect(decodeToken).toBeTruthy()
        expect(JSON.stringify(decodedToken.payload)).toBe(JSON.stringify(sampleDecodedToken.payload))
    })

    test('expandedToken', async () => {
        const tokenSigner = new TokenSigner('ES256K', rawPrivateKey)
        const tokenVerifier = new TokenVerifier('ES256K', rawPublicKey)

        const token = await tokenSigner.sign(sampleDecodedToken.payload, true)
        expect(token).toBeTruthy()
        expect(typeof token).toBe('object')
        
        const verified = await tokenVerifier.verify(token)
        expect(verified).toBe(true)

        const signedToken = await tokenSigner.sign(sampleDecodedToken.payload, true)
        expect(signedToken).toBeTruthy()
    })
}
