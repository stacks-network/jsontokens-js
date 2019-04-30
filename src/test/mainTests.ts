import test from 'tape'
import base64url from 'base64url'

import {
    TokenSigner, TokenVerifier, decodeToken, createUnsecuredToken
} from '../index'

export function runMainTests() {
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

    test('TokenSigner', (t) => {
        t.plan(7)

        const tokenSigner = new TokenSigner('ES256K', rawPrivateKey)
        t.ok(tokenSigner, 'token signer should have been created')

        const token = tokenSigner.sign(sampleDecodedToken.payload)
        t.ok(token, 'token should have been created')
        t.equal(typeof token, 'string', 'token should be a string')
        t.equal(token.split('.').length, 3, 'token should have 3 parts')
        //console.log(token)

        const decodedToken = decodeToken(token)
        t.equal(
            JSON.stringify(decodedToken.header),
            JSON.stringify(sampleDecodedToken.header),
            'decodedToken header should match the reference header'
        )
        t.equal(
            JSON.stringify(decodedToken.payload),
            JSON.stringify(sampleDecodedToken.payload),
            'decodedToken payload should match the reference payload'
        )

        t.throws(() => {
            new TokenSigner('ES256K', undefined) 
        }, /MissingParametersError/, 'Should throw MissingParametersError')
    })


    test('TokenSigner custom header', (t) => {
        t.plan(7)

        const tokenSigner = new TokenSigner('ES256K', rawPrivateKey)
        t.ok(tokenSigner, 'token signer should have been created')

        const token = tokenSigner.sign(sampleDecodedToken.payload, undefined, { test: 'TestHeader' })
        t.ok(token, 'token should have been created')
        t.equal(typeof token, 'string', 'token should be a string')
        t.equal(token.split('.').length, 3, 'token should have 3 parts')
        //console.log(token)

        const decodedToken = decodeToken(token)
        t.equal(
            JSON.stringify(decodedToken.header),
            JSON.stringify(Object.assign({},
                                         sampleDecodedToken.header,
                                         { test: 'TestHeader' })),
            'decodedToken header should match the reference header'
        )
        t.equal(
            JSON.stringify(decodedToken.payload),
            JSON.stringify(sampleDecodedToken.payload),
            'decodedToken payload should match the reference payload'
        )

        t.throws(() => {
          new TokenSigner('ES256K', undefined)
        }, /MissingParametersError/, 'Should throw MissingParametersError')
    })

    test('createUnsecuredToken', (t) => {
        t.plan(3)

        const unsecuredToken = createUnsecuredToken(
            sampleDecodedToken.payload)
        t.ok(unsecuredToken, 'unsecured token should have been created')
        t.equal(unsecuredToken,
            base64url.encode(JSON.stringify({typ: 'JWT', alg: 'none'})) + '.' + sampleToken.split('.')[1] + '.',
            'unsigned token should equal reference')

        const decodedToken = decodeToken(unsecuredToken)
        t.ok(decodedToken, 'token should have been decoded')
    })

    test('TokenVerifier', (t) => {
        t.plan(3)

        const tokenVerifier = new TokenVerifier('ES256K', rawPublicKey)
        t.ok(tokenVerifier, 'token verifier should have been created')

        const verified = tokenVerifier.verify(sampleToken)
        t.equal(verified, true, 'token should have been verified')

        const tokenSigner = new TokenSigner('ES256K', rawPrivateKey)
        const newToken = tokenSigner.sign(sampleDecodedToken.payload)
        const newTokenVerified = tokenVerifier.verify(newToken)
        t.equal(newTokenVerified, true, 'token should have been verified')
    })

    test('decodeToken', (t) => {
        t.plan(2)

        const decodedToken = decodeToken(sampleToken)
        t.ok(decodedToken, 'token should have been decoded')
        t.equal(
            JSON.stringify(decodedToken.payload),
            JSON.stringify(sampleDecodedToken.payload),
            'decodedToken payload should match the reference payload'
        )
    })

    test('expandedToken', (t) => {
        t.plan(3)

        const tokenSigner = new TokenSigner('ES256K', rawPrivateKey)
        const tokenVerifier = new TokenVerifier('ES256K', rawPublicKey)

        const token = tokenSigner.sign(sampleDecodedToken.payload, true)
        t.ok(token, 'expanded token should have been created')
        t.equal(typeof token, 'object', 'expanded token should be an Object')

        console.log(JSON.stringify(token))

        const verified = tokenVerifier.verify(token)
        t.equal(verified, true, 'token should have been verified')

        tokenSigner.sign(sampleDecodedToken.payload, true)
    })
}
