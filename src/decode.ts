import base64url from 'base64url'

export interface TokenInterface {
    header: {
      [key: string]: any;
      alg?: string;
      typ?: string;
    };
    payload: {
      [key: string]: any;
      iss?: string;
      jti?: string;
      iat?: string | number;
      exp?: string | number;
    } | string;
    signature: string;
}

export function decodeToken(token: string | TokenInterface): TokenInterface {
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
        if (typeof token.payload !== 'string') {
            throw new Error('Expected token payload to be a base64 or json string')
        }
        let payload = token.payload
        if (token.payload[0] !== '{') {
            payload = base64url.decode(payload)
        }

        const allHeaders: any[] = []
        token.header.map((headerValue: string) => {
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
