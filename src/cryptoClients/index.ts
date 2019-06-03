import { SECP256K1Client } from './secp256k1'

const cryptoClients: {
  [index: string]: typeof SECP256K1Client, 
  ES256K: typeof SECP256K1Client
} = {
  ES256K: SECP256K1Client
}

export {
  SECP256K1Client,
  cryptoClients
}
