'use strict'

import base64url from 'base64url'

export function decodeToken(token) {
    if (typeof token === 'string') {
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
    } else if (typeof token === 'object') {
        let payload = token.payload
        if (token.payload[0] !== '{') {
            payload = base64url.decode(payload)
        }

        const allHeaders = []
        token.header.map((headerValue) => {
            const header = JSON.parse(base64url.decode(headerValue))
            allHeaders.push(header)
        })

        return {
            header: allHeaders,
            payload: JSON.parse(payload),
            signature: token.signature
        }
    }
}
