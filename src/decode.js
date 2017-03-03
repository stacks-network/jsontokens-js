'use strict'

import base64url from 'base64url'
import { InvalidTokenError } from './errors'

export function decodeToken(token) {
  // decompose the token into parts
  const tokenParts = token.split('.')

  if (tokenParts.length !== 3) {
    throw new InvalidTokenError('tokens should have 3 parts')
  }

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