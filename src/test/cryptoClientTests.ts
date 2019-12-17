import { SECP256K1Client as secp256k1 } from '../index'
import { hashSha256Async } from '../cryptoClients/sha256'

describe('SECP256k1 tests', () => {
  runSECP256k1Tests()
})

function runSECP256k1Tests() {
  const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
  const privateKey2 = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f01'
  const privateKey3 = '494651c7602fa047590386dbf48ad47ecd2a25ae4f0f39334e57f5bc62771f'
  const publicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
  const publicKey3  = '02ccaa8fb748f1b1d260178092b8eb96be96097fb437a247ed03dbaf13fa5a5a35'
  const uncompresedPublicKey = '04fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea535847946393f8145252eea68afe67e287b3ed9b31685ba6c3b00060a73b9b1242d68f7'

  test('derivePublicKey 1', () => {
    const derivedPublicKey = secp256k1.derivePublicKey(privateKey)
    expect(derivedPublicKey).toBeTruthy()
    expect(derivedPublicKey).toBe(publicKey)
  })

  test('derivePublicKey 2', () => {
    const derivedPublicKey2 = secp256k1.derivePublicKey(privateKey2)
    expect(derivedPublicKey2).toBeTruthy()
    expect(derivedPublicKey2).toBe(publicKey)
  })

  test('derivePublicKey 3', () => {
    const derivedPublicKey3 = secp256k1.derivePublicKey(privateKey3)
    expect(derivedPublicKey3).toBeTruthy()
    expect(derivedPublicKey3).toBe(publicKey3)
  })

  test('derivePublicKey uncompressed', () => {
    const derivedUncompressedPublicKey = secp256k1.derivePublicKey(privateKey, false)
    expect(derivedUncompressedPublicKey).toBeTruthy()
    expect(derivedUncompressedPublicKey).toBe(uncompresedPublicKey)
  })

  test('createHash + signHash', async () => {
    const message = 'Hello, world!'
    const referenceSignature = '3046022100997b6210d959e67ad9cee01589d01daf0fe77ce0f002d040d769171c33504860022100e35a03d2354074d7e49d0499568e331be39af901a543d1731ea1ff8f423f21ab'

    const hash = await hashSha256Async(message)
    const signature = secp256k1.signHash(hash, privateKey, 'der')

    expect(signature).toBeTruthy()
    expect(typeof signature).toBe('string')
    expect(signature).toBe(referenceSignature)
  })
}
