# wasm-bindgen nodejs/browser bindings for babyjubjub_rs-with-elgamal

```typescript 
export function enableErrors(): void;
export function msgToPoint(m: string): any;
export function pointToMsg(point: any): any;
export function encryptPoint(msg: any, pubkey: any, nonce: string): any;
export function finalDecrypt(encryptedMsg: any, decryptShares: any, numSharesNeeded: number): any;
export function random_node(): any;
export function node_from_seed(seed: Uint8Array): any;
export function read_node(node: any): any;
export function litKeygen(seed: Uint8Array): any;
export function auditorKeygen(seed: Uint8Array): any;
export function litDecrypt(seed: Uint8Array, auditorKeygenEvalAt1: any, encryptedC1: any): any;
export function auditorDecrypt(seed: Uint8Array, litKeygenEvalAt2: any, encrypted: any, litPartialDecryption: any): any;
export function auditorPubkeyShare(seed: Uint8Array, litKeygenEvalAt2: any): any;
export function litPubkeyShare(seed: Uint8Array, auditorKeygenEvalAt1: any): any;
export function sharedPubkey(pubkeyShares: any): any;
```


build for the browser:
```bash 
yarn && yarn build-web
```
to test that it works run
```bash
yarn test-html
```

Build for nodejs:
```bash 
yarn && yarn build-nodejs
```
to test that it works run
```bash
yarn test-nodejs
```



# Todo support lit bundling/binding.