'use strict'

module.exports = {
    TokenSigner: require('./lib/signer'),
    TokenVerifier: require('./lib/verifier'),
    decodeToken: require('./lib/decode'),
    MissingParametersError: require('./lib/errors').MissingParametersError,
    SECP256K1Client: require('./lib/signing-algorithms/secp256k1')
}
