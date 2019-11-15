import base64url from 'base64url'

import {
    TokenSigner, TokenVerifier, decodeToken, createUnsecuredToken, MissingParametersError
} from '../index'

import * as webcrypto from '@peculiar/webcrypto'

describe('main tests - node.js crypto', () => {
    let origGlobalCrypto: { defined: boolean, value: any }
    beforeAll(() => {
        origGlobalCrypto = {
            defined: 'crypto' in global,
            value: (global as any)['crypto']
        }
        delete (global as any)['crypto'];
        (global as any)['crypto'] = new webcrypto.Crypto()
    })
    afterAll(() => {
        if (origGlobalCrypto.defined) {
            (global as any)['crypto']  = origGlobalCrypto.value
        } else {
            delete (global as any)['crypto'] 
        }
    })
    runMainTests()
})

describe('main tests - sha.js crypto', () => {
    let origCreateHash: typeof import('crypto').createHash
    beforeAll(() => {
        const nodeCrypto = require('crypto') as typeof import('crypto')
        origCreateHash = nodeCrypto.createHash
        delete nodeCrypto.createHash
    })
    afterAll(() => {
        const nodeCrypto = require('crypto') as typeof import('crypto')
        nodeCrypto.createHash = origCreateHash
    })
    runMainTests()
})

describe('main tests - web crypto', () => {
    beforeAll(() => {
        (global as any)['crypto'] = new webcrypto.Crypto()
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

        const token = await tokenSigner.signAsync(sampleDecodedToken.payload, false)
        const token1 = tokenSigner.sign(sampleDecodedToken.payload, false)
        expect(token).toStrictEqual(token1)
        expect(token).toBeTruthy()
        expect(typeof token).toBe('string')
        expect(token.split('.').length).toBe(3)

        const decodedToken = decodeToken(token)
        expect(JSON.stringify(decodedToken.header)).toBe(JSON.stringify(sampleDecodedToken.header))
        expect(JSON.stringify(decodedToken.payload)).toBe(JSON.stringify(sampleDecodedToken.payload))
        expect(() => new TokenSigner('ES256K', undefined)).toThrowError(MissingParametersError)
    })


    test('TokenSigner custom header', async () => {
        const tokenSigner = new TokenSigner('ES256K', rawPrivateKey)
        expect(tokenSigner).toBeTruthy()

        const token = await tokenSigner.signAsync(sampleDecodedToken.payload, false, { test: 'TestHeader' })
        const token1 = tokenSigner.sign(sampleDecodedToken.payload, false, { test: 'TestHeader' })
        expect(token).toStrictEqual(token1)
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

        const verified = await tokenVerifier.verifyAsync(sampleToken)
        const verified1 = await tokenVerifier.verify(sampleToken)
        expect(verified).toStrictEqual(verified1)
        expect(verified).toBe(true)

        const tokenSigner = new TokenSigner('ES256K', rawPrivateKey)
        const newToken = await tokenSigner.signAsync(sampleDecodedToken.payload, false)
        const newToken1 = tokenSigner.sign(sampleDecodedToken.payload, false)
        expect(newToken).toStrictEqual(newToken1)
        expect(newToken).toBeTruthy()

        const newTokenVerified = await tokenVerifier.verifyAsync(newToken)
        const newTokenVerified1 = tokenVerifier.verify(newToken)
        expect(newTokenVerified).toStrictEqual(newTokenVerified1)
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

        const token = await tokenSigner.signAsync(sampleDecodedToken.payload, true)
        const token1 = tokenSigner.sign(sampleDecodedToken.payload, true)
        expect(token).toStrictEqual(token1)
        expect(token).toBeTruthy()
        expect(typeof token).toBe('object')
        
        const verified = await tokenVerifier.verifyAsync(token)
        const verified1 = tokenVerifier.verify(token)
        expect(verified).toStrictEqual(verified1)
        expect(verified).toBe(true)

        const signedToken = await tokenSigner.signAsync(sampleDecodedToken.payload, true)
        const signedToken1 = tokenSigner.sign(sampleDecodedToken.payload, true)
        expect(signedToken).toStrictEqual(signedToken1)
        expect(signedToken).toBeTruthy()
    })
}
