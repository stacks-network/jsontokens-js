module.exports = {
  entry: './src/index.ts',
  module: {
    rules: [
      {
        test: /\.ts?$/,
        exclude: /node_modules/,
        use: { loader: 'ts-loader' }
      },
      {
        test: /\.js$/,
        use: {
          loader: 'babel-loader',
          options: { presets: ['@babel/preset-env'] }
        }
      }
    ]
  },
  resolve: { extensions: ['.ts', '.js'] },
  output: {
    filename: 'jsontokens.js',
    path: require('path').resolve(__dirname, 'dist'),
    library: 'jsontokens',
    libraryTarget: 'umd',
    globalObject: 'this'
  }
}
