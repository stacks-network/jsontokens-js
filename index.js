'use strict'

module.exports = {
    TokenSigner: require('./lib/signer'),
    TokenVerifier: require('./lib/verifier'),
    decodeToken: require('./lib/decode'),
    MissingParametersError: require('./lib/errors').MissingParametersError,
    ES256kClient: require('./lib/crypto-clients').es256k
}
