export {
    TokenSigner, TokenVerifier, decodeToken,
    MissingParametersError
} from '../index'

import {
  SECP256K1Client
} from '../index'

export { SECP256K1Client }

const hash = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const rawPrivateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'

console.log('hash:')
console.log(hash)

console.log('raw private key:')
console.log(rawPrivateKey)

const signature = SECP256K1Client.signHash(hash, rawPrivateKey)

console.log('signature:')
console.log(signature)
