'use strict'

function MissingParametersError(message) {
    this.name = 'MissingParametersError'
    this.message = (message || '')
}
MissingParametersError.prototype = new Error()

module.exports = {
    MissingParametersError: MissingParametersError
}