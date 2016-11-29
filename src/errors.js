'use strict'

export class MissingParametersError extends Error {
  constructor(message) {
    super()
    this.name = 'MissingParametersError'
    this.message = (message || '')
  }
}