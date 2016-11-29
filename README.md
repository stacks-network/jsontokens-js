# JSON Tokens JS

[![CircleCI](https://img.shields.io/circleci/project/blockstack/jsontokens-js/master.svg)](https://circleci.com/gh/blockstack/jsontokens-js/tree/master)
[![npm](https://img.shields.io/npm/l/jsontokens.svg)](https://www.npmjs.com/package/jsontokens)
[![npm](https://img.shields.io/npm/v/jsontokens.svg)](https://www.npmjs.com/package/jsontokens)
[![npm](https://img.shields.io/npm/dm/jsontokens.svg)](https://www.npmjs.com/package/jsontokens)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

node.js library for signing, decoding, and verifying JSON Web Tokens (JWTs)

### Installation

```
npm install jsontokens
```

### Signing Tokens

```js
import { TokenSigner } from 'jsontokens'

const rawPrivateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const tokenPayload = {"issuedAt": "1440713414.85", "challenge": "7cd9ed5e-bb0e-49ea-a323-f28bde3a0549", "issuer": {"publicKey": "03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479", "chainPath": "bd62885ec3f0e3838043115f4ce25eedd22cc86711803fb0c19601eeef185e39", "publicKeychain": "xpub661MyMwAqRbcFQVrQr4Q4kPjaP4JjWaf39fBVKjPdK6oGBayE46GAmKzo5UDPQdLSM9DufZiP8eauy56XNuHicBySvZp7J5wsyQVpi2axzZ", "blockchainid": "ryan"}}
const token = new TokenSigner('ES256k', rawPrivateKey).sign(tokenPayload)
```

##### Example output:

```js
> console.log(token)
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3N1ZWRBdCI6IjE0NDA3MTM0MTQuODUiLCJjaGFsbGVuZ2UiOiI3Y2Q5ZWQ1ZS1iYjBlLTQ5ZWEtYTMyMy1mMjhiZGUzYTA1NDkiLCJpc3N1ZXIiOnsicHVibGljS2V5IjoiMDNmZGQ1N2FkZWMzZDQzOGVhMjM3ZmU0NmIzM2VlMWUwMTZlZGE2YjU4NWMzZTI3ZWE2NjY4NmMyZWE1MzU4NDc5IiwiY2hhaW5QYXRoIjoiYmQ2Mjg4NWVjM2YwZTM4MzgwNDMxMTVmNGNlMjVlZWRkMjJjYzg2NzExODAzZmIwYzE5NjAxZWVlZjE4NWUzOSIsInB1YmxpY0tleWNoYWluIjoieHB1YjY2MU15TXdBcVJiY0ZRVnJRcjRRNGtQamFQNEpqV2FmMzlmQlZLalBkSzZvR0JheUU0NkdBbUt6bzVVRFBRZExTTTlEdWZaaVA4ZWF1eTU2WE51SGljQnlTdlpwN0o1d3N5UVZwaTJheHpaIiwiYmxvY2tjaGFpbmlkIjoicnlhbiJ9fQ.oO7ROPKq3T3X0azAXzHsf6ub6CYy5nUUFDoy8MS22B3TlYisqsBrRtzWIQcSYiFXLytrXwAdt6vjehj3OFioDQ
```

### Decoding Tokens

```js
import { decodeToken } = from 'jsontokens'
const tokenData = decodeToken(token)
```

##### Example output:

```js
> console.log(tokenData)
{ header: { alg: 'ES256', typ: 'JWT' },
  payload: 
   { issuedAt: '1440713414.85',
     challenge: '7cd9ed5e-bb0e-49ea-a323-f28bde3a0549',
     issuer: 
      { publicKey: '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479',
        chainPath: 'bd62885ec3f0e3838043115f4ce25eedd22cc86711803fb0c19601eeef185e39',
        publicKeychain: 'xpub661MyMwAqRbcFQVrQr4Q4kPjaP4JjWaf39fBVKjPdK6oGBayE46GAmKzo5UDPQdLSM9DufZiP8eauy56XNuHicBySvZp7J5wsyQVpi2axzZ',
        blockchainid: 'ryan' } },
  signature: 'oO7ROPKq3T3X0azAXzHsf6ub6CYy5nUUFDoy8MS22B3TlYisqsBrRtzWIQcSYiFXLytrXwAdt6vjehj3OFioDQ' }
```

### Verifying Tokens

```js
import { TokenVerifier } from 'jsontokens'
const rawPublicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
const verified = new TokenVerifier('ES256k', rawPublicKey).verify(token)
```

##### Example output:

```js
> console.log(verified)
true
```
