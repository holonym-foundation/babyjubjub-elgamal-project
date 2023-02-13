const path = require('path');
const glob = require('glob');
const webpack = require('webpack');
const WasmPackPlugin = require('@wasm-tool/wasm-pack-plugin');

module.exports = {
    entry: process.env.HOLONYM_TEST === 'true' ? glob.sync('./test-js/*.js') : './src-js/index.js',
    output: {
        // path: path.resolve(__dirname, 'dist'),
        filename: process.env.HOLONYM_TEST === 'true' ? 'test.js' : 'main.js',
    },
    module: {
        rules: [
            {
                test: /\.ts$/,
                loader: 'ts-loader',
                options: {
                    configFile: 'tsconfig.json',
                },
            },
        ],
        defaultRules: [
            {
                test: /\.wasm$/,
                type: "asset/inline",
            },
            // {
            //     test: /\.wasm$/,
            //     loader: 'raw-loader',
            // }
        ]
    },
    plugins: [
        new WasmPackPlugin({
            crateDirectory: path.resolve(__dirname, "."),
            forceMode: "production"
        }),
        new webpack.optimize.LimitChunkCountPlugin({
            maxChunks: 1, // disable creating additional chunks
        }),
        // Have this example work in Edge which doesn't ship `TextEncoder` or
        // `TextDecoder` at this time.
        new webpack.ProvidePlugin({
          TextDecoder: ['text-encoding', 'TextDecoder'],
          TextEncoder: ['text-encoding', 'TextEncoder']
        })
    ],
    mode: 'production',
    target: 'node',
    experiments: {
        asyncWebAssembly: true
   }
};