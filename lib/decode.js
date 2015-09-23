'use strict'

var base64url = require('base64url')

function decodeToken(token) {
    // decompose the token into parts
    var tokenParts = token.split('.'),
        header = JSON.parse(base64url.decode(tokenParts[0])),
        payload = JSON.parse(base64url.decode(tokenParts[1])),
        signature = tokenParts[2]

    // return the token object
    return {
        header: header,
        payload: payload,
        signature: signature
    }
}

module.exports = decodeToken