const path = require('path');
const webpack = require('webpack');

module.exports = {
  mode: 'development',
  entry: './index.js',
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env']
          }
        }
      },
      {
        test: /\.css$/,
        use: [
          { loader: "style-loader" },
          { loader: "css-loader" }
        ]
      }
    ]
  },
  output: {
    path: path.resolve(__dirname, 'js'),
    filename: 'index.js',
  },
  devServer: {
    contentBase: false,
  }
};
