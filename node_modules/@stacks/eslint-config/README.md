# @stacks/eslint-config

A set of ESLint configuration and rules for use in Stacks projects.

## Installation

```bash
yarn add --dev eslint @stacks/eslint-config
# or, with npm
npm install --save-dev eslint @stacks/eslint-config
```

Then, create or modify your `.eslintrc.js` file to extend this config:

```js
module.exports = {
  extends: '@stacks/eslint-config',
  parser: '@typescript-eslint/parser',
  parserOptions: {
    tsconfigRootDir: __dirname,
    project: ['./tsconfig.json'],
    ecmaVersion: 2019,
    sourceType: 'module',
  },
};
```

Finally, modify your `package.json` file to use our prettier config, which is already installed as a dependency of this package.

```json
{
  "prettier": "@stacks/prettier-config"
}
```

## Overriding rules

This configuration includes a bunch of rules that have become standard in our JavaScript projects. However, if you feel the need to override a rule, you can always do so by simply adding `rules` to your `.eslintrc.js` file.

```js
module.exports = {
  extends: ['@stacks/eslint-config'],
  rules: {
    '@typescript-eslint/no-use-before-define': [2],
  },
};
```
