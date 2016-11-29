'use strict'

import base64url from 'base64url'

export function decodeToken(token) {
    // decompose the token into parts
    const tokenParts = token.split('.')
    const header = JSON.parse(base64url.decode(tokenParts[0]))
    const payload = JSON.parse(base64url.decode(tokenParts[1]))
    const signature = tokenParts[2]

    // return the token object
    return {
        header: header,
        payload: payload,
        signature: signature
    }
}