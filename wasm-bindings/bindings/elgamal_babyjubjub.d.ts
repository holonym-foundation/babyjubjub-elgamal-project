/* tslint:disable */
/* eslint-disable */
/**
*/
export function enableErrors(): void;
/**
* @param {string} m
* @returns {any}
*/
export function msgToPoint(m: string): any;
/**
* @param {any} point
* @returns {any}
*/
export function pointToMsg(point: any): any;
/**
* @param {any} msg
* @param {any} pubkey
* @param {string} nonce
* @returns {any}
*/
export function encryptPoint(msg: any, pubkey: any, nonce: string): any;
/**
* @param {any} encryptedMsg
* @param {any} decryptShares
* @param {number} numSharesNeeded
* @returns {any}
*/
export function finalDecrypt(encryptedMsg: any, decryptShares: any, numSharesNeeded: number): any;
/**
* @returns {any}
*/
export function random_node(): any;
/**
* @param {Uint8Array} seed
* @returns {any}
*/
export function node_from_seed(seed: Uint8Array): any;
/**
* @param {any} node
* @returns {any}
*/
export function read_node(node: any): any;
/**
* @param {Uint8Array} seed
* @returns {any}
*/
export function litKeygen(seed: Uint8Array): any;
/**
* @param {Uint8Array} seed
* @returns {any}
*/
export function auditorKeygen(seed: Uint8Array): any;
/**
* @param {Uint8Array} seed
* @param {any} auditorKeygenEvalAt1
* @param {any} encryptedC1
* @returns {any}
*/
export function litDecrypt(seed: Uint8Array, auditorKeygenEvalAt1: any, encryptedC1: any): any;
/**
* @param {Uint8Array} seed
* @param {any} litKeygenEvalAt2
* @param {any} encrypted
* @param {any} litPartialDecryption
* @returns {any}
*/
export function auditorDecrypt(seed: Uint8Array, litKeygenEvalAt2: any, encrypted: any, litPartialDecryption: any): any;
/**
* @param {Uint8Array} seed
* @param {any} litKeygenEvalAt2
* @returns {any}
*/
export function auditorPubkeyShare(seed: Uint8Array, litKeygenEvalAt2: any): any;
/**
* @param {Uint8Array} seed
* @param {any} auditorKeygenEvalAt1
* @returns {any}
*/
export function litPubkeyShare(seed: Uint8Array, auditorKeygenEvalAt1: any): any;
/**
* @param {any} pubkeyShares
* @returns {any}
*/
export function sharedPubkey(pubkeyShares: any): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly msgToPoint: (a: number, b: number) => number;
  readonly pointToMsg: (a: number) => number;
  readonly encryptPoint: (a: number, b: number, c: number, d: number) => number;
  readonly finalDecrypt: (a: number, b: number, c: number) => number;
  readonly random_node: () => number;
  readonly node_from_seed: (a: number, b: number) => number;
  readonly read_node: (a: number) => number;
  readonly litKeygen: (a: number, b: number) => number;
  readonly auditorKeygen: (a: number, b: number) => number;
  readonly litDecrypt: (a: number, b: number, c: number, d: number) => number;
  readonly auditorDecrypt: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly auditorPubkeyShare: (a: number, b: number, c: number) => number;
  readonly litPubkeyShare: (a: number, b: number, c: number) => number;
  readonly sharedPubkey: (a: number) => number;
  readonly enableErrors: () => void;
  readonly __wbindgen_malloc: (a: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __wbindgen_free: (a: number, b: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function init (module_or_path: InitInput | Promise<InitInput>): Promise<InitOutput>;
