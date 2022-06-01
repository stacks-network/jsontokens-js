# Changelog
All notable changes to the project will be documented in this file.

## [3.1.1](https://github.com/stacks-network/jsontokens-js/compare/v3.1.0...v3.1.1) (2022-06-01)


### Bug Fixes

* allow compressed private keys ([a7cfc6a](https://github.com/stacks-network/jsontokens-js/commit/a7cfc6ae833e661bfee51f6baf7490b3c41b14f5))

# [3.1.0](https://github.com/stacks-network/jsontokens-js/compare/v3.0.0...v3.1.0) (2022-05-31)


### Features

* replace crypto dependencies ([50bc8eb](https://github.com/stacks-network/jsontokens-js/commit/50bc8eba918e23adaaf2794d75d07f6b8635cffc))

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0]
### Changed
- Added async functions that use Web Crypto API used for hashing, if available. Otherwise uses the Node.js `crypto` module. 

## [2.0.3]
### Changed
- No longer exporting buggy `@types/bn.js` package. Lib consumers no longer require enabling
  synthetic default imports. 

## [2.0.2]
### Changed
- Fixed bug with type packages listed in `devDependencies` instead of `dependencies`.

## [2.0.1]
### Added
- Added types to [TokenInterface](https://github.com/blockstack/jsontokens-js/issues/39).

## [2.0.0]
### Changed
- Ported to Typescript. 

## [1.0.0]
### Changed
- We now have an .eslintrc definition and code that passes that linting spec.

## [0.8.0]
### Added
- You can now add custom header fields to the JWS header by passing
  an object to the `TokenSigner.sign()` method's `customHeader` parameter.

### Changed
- Use `Buffer.from` instead of deprecated `new Buffer()`
