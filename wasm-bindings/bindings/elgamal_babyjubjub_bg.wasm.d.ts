/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export function msgToPoint(a: number, b: number): number;
export function pointToMsg(a: number): number;
export function encryptPoint(a: number, b: number, c: number, d: number): number;
export function finalDecrypt(a: number, b: number, c: number): number;
export function random_node(): number;
export function node_from_seed(a: number, b: number): number;
export function read_node(a: number): number;
export function litKeygen(a: number, b: number): number;
export function auditorKeygen(a: number, b: number): number;
export function litDecrypt(a: number, b: number, c: number, d: number): number;
export function auditorDecrypt(a: number, b: number, c: number, d: number, e: number): number;
export function auditorPubkeyShare(a: number, b: number, c: number): number;
export function litPubkeyShare(a: number, b: number, c: number): number;
export function sharedPubkey(a: number): number;
export function enableErrors(): void;
export function __wbindgen_malloc(a: number): number;
export function __wbindgen_realloc(a: number, b: number, c: number): number;
export function __wbindgen_exn_store(a: number): void;
export function __wbindgen_free(a: number, b: number): void;
