const path = require('path');
const glob = require('glob');
const webpack = require('webpack');
const WasmPackPlugin = require('@wasm-tool/wasm-pack-plugin');

let entry;
let output;
switch(process.env.HOLONYM_BUILD_MODE) {
    case 'test':
        entry = glob.sync('./test-js/*.js');
        output = { filename: 'test.js' };
        break;
    case 'lit':
        entry = './src-js/lit-index.js';
        output = { filename: 'lit-standalone-script.js' };
        break;
    // By default, build a library from wrapper.js using these guidelines https://webpack.js.org/guides/author-libraries/
    default:
        entry = './src-js/wrapper.js';
        output = { 
            globalObject: 'this',
            filename: 'node-package/threshold-eg-babyjub.js',
            library : {
                name: 'threshold-eg-babyjub',
                type: 'umd'
            },
        };
        break;
}
module.exports = {
    entry: entry,
    output: output,
    // output: {
    //     // path: path.resolve(__dirname, 'dist'),
    //     filename: output
    // },
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