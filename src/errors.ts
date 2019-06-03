export class MissingParametersError extends Error {
  constructor(message: string) {
    super()
    this.name = 'MissingParametersError'
    this.message = (message || '')
  }
}

export class InvalidTokenError extends Error {
  constructor(message: string) {
    super()
    this.name = 'InvalidTokenError'
    this.message = (message || '')
  }
}
