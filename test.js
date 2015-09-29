'use strict'

var test = require('tape'),
    Tokenizer = require('./index').Tokenizer,
    TokenSigner = require('./index').TokenSigner,
    TokenVerifier = require('./index').TokenVerifier,
    decodeToken = require('./index').decodeToken,
    MissingParametersError = require('./index').MissingParametersError

var tokenizer = new Tokenizer('ES256k')

var rawPrivateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f',
    rawPublicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479',
    sampleToken = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3N1ZWRBdCI6IjE0NDA3MTM0MTQuODUiLCJjaGFsbGVuZ2UiOiI3Y2Q5ZWQ1ZS1iYjBlLTQ5ZWEtYTMyMy1mMjhiZGUzYTA1NDkiLCJpc3N1ZXIiOnsicHVibGljS2V5IjoiMDNmZGQ1N2FkZWMzZDQzOGVhMjM3ZmU0NmIzM2VlMWUwMTZlZGE2YjU4NWMzZTI3ZWE2NjY4NmMyZWE1MzU4NDc5IiwiY2hhaW5QYXRoIjoiYmQ2Mjg4NWVjM2YwZTM4MzgwNDMxMTVmNGNlMjVlZWRkMjJjYzg2NzExODAzZmIwYzE5NjAxZWVlZjE4NWUzOSIsInB1YmxpY0tleWNoYWluIjoieHB1YjY2MU15TXdBcVJiY0ZRVnJRcjRRNGtQamFQNEpqV2FmMzlmQlZLalBkSzZvR0JheUU0NkdBbUt6bzVVRFBRZExTTTlEdWZaaVA4ZWF1eTU2WE51SGljQnlTdlpwN0o1d3N5UVZwaTJheHpaIiwiYmxvY2tjaGFpbmlkIjoicnlhbiJ9fQ.oO7ROPKq3T3X0azAXzHsf6ub6CYy5nUUFDoy8MS22B3TlYisqsBrRtzWIQcSYiFXLytrXwAdt6vjehj3OFioDQ',
    sampleDecodedToken = {
      header: { typ: 'JWT', alg: 'ES256' },
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

test('testSign', function(t) {
    t.plan(5)

    var encodedToken = tokenizer.sign(sampleDecodedToken.payload, rawPrivateKey)
    t.ok(encodedToken, 'token should have been created')
    t.equal(typeof encodedToken, 'string', 'token should be a string')
    
    var decodedToken = decodeToken(encodedToken)
    t.equal(JSON.stringify(decodedToken.header), JSON.stringify(sampleDecodedToken.header), 'decodedToken header should match the reference header')
    t.equal(JSON.stringify(decodedToken.payload), JSON.stringify(sampleDecodedToken.payload), 'decodedToken payload should match the reference payload')

    try {
        encodedToken = tokenizer.sign(sampleDecodedToken.payload)
    } catch(err) {
        t.equal(err.name, 'MissingParametersError', 'token signing without a private key should throw an error')
    }
})

test('testDecode', function(t) {
    t.plan(2)

    var decodedToken = decodeToken(sampleToken)
    t.ok(decodedToken, 'token should have been decoded')
    t.equal(JSON.stringify(decodedToken.payload), JSON.stringify(sampleDecodedToken.payload), 'decodedToken payload should match the reference payload')
})

test('testVerify', function(t) {
    t.plan(2)

    var tokenVerified = tokenizer.verify(sampleToken, rawPublicKey)
    t.equal(tokenVerified, true, 'token should have been verified')

    try {
        tokenVerified = tokenizer.verify(sampleToken)
    } catch(err) {
        t.equal(err.name, 'MissingParametersError', 'token verification without a public key should throw an error')
    }
})

test('tokenSigner', function(t) {
    t.plan(5)

    var tokenSigner = new TokenSigner('ES256k', rawPrivateKey)
    t.ok(tokenSigner, 'token signer should have been created')

    var token = tokenSigner.sign(sampleDecodedToken.payload)
    t.ok(token, 'token should have been created')
    t.equal(typeof token, 'string', 'token should be a string')
    
    var decodedToken = decodeToken(token)
    t.equal(JSON.stringify(decodedToken.header), JSON.stringify(sampleDecodedToken.header), 'decodedToken header should match the reference header')
    t.equal(JSON.stringify(decodedToken.payload), JSON.stringify(sampleDecodedToken.payload), 'decodedToken payload should match the reference payload')

})

test('tokenVerifier', function(t) {
    t.plan(2)

    var tokenVerifier = new TokenVerifier('ES256k', rawPublicKey)
    t.ok(tokenVerifier, 'token verifier should have been created')
    
    var verified = tokenVerifier.verify(sampleToken)
    t.equal(verified, true, 'token should have been verified')
})
