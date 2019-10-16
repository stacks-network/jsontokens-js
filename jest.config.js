module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  coverageDirectory: './coverage/',
  collectCoverage: true,
  testMatch: ['**/test/**/*.ts'],
  testPathIgnorePatterns: ['/node_modules/', 'browserifyApp.ts']
}
