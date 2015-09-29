'use strict'

module.exports = {
    TokenSigner: require('./lib/signer'),
    TokenVerifier: require('./lib/verifier'),
    decodeToken: require('./lib/decode'),
    MissingParametersError: require('./lib/errors').MissingParametersError,
    // Deprecated
    Tokenizer: require('./lib/tokenizer')
}
