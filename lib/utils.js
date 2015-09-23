'use strict'

function assert(val, msg) {
    if (!val) {
        throw new Error(msg || 'Assertion failed')
    }
}

module.exports = {
    assert: assert
}