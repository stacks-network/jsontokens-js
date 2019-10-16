import { runSECP256k1Tests } from './cryptoClientTests'
import { runMainTests } from './mainTests'

// Uncomment to provide tests against the WebCrypto APIs. 
// TODO: tape.js makes it hard to run tests twice, need to refactor to jest or mocha.
// import * as crypto from '@peculiar/webcrypto'
// Object.defineProperty(global, 'crypto', { value: new crypto.Crypto() })

runMainTests()
runSECP256k1Tests()
