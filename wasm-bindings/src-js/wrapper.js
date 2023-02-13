// https://stackoverflow.com/a/71673305/14039774 is gold 
import init from '../bindings/elgamal_babyjubjub';
import wasmData from '../bindings/elgamal_babyjubjub_bg.wasm';
const { randomBytes } = require("crypto");

const b = init(wasmData);
// let rust = null;

// async function init () {
//   if(rust) {
//     return 
//   } else {
//     b = await rust_;
//     console.log("b", b.enableErrors)
//     console.log("msgToPoint", b.msgToPoint);
//     try {
//       console.log(b.msgToPoint("69"))
//       // b.enableErrors();
//     } catch(err) {
//       console.error("err", Object.keys(err))
//     }
//   }
// }

// class Lit {
//     // Seed is a U8Array / Buffer
//     constructor(seed) {
//         this.seed = seed;
//     }

//     // Results from Lit and Auditor keygen can be combined to create keyshares
//     async keygen () {
//       await init();
//       return rust.litKeygen(this.seed);
//     }

//     async pubkey (auditorKeygenForMe) {
//         await init();
//         return rust.litPubkeyShare(this.seed, auditorKeygenForMe); 
//     }
    
//     async partialDecrypt (auditorKeygenForMe, encrypted) {
//         await init();
//         return rust.litDecrypt(this.seed, auditorKeygenForMe, encrypted);
//     }
    
// }

// class Auditor {
//     // Seed is a U8Array / Buffer
//     constructor(seed) {
//         this.seed = seed;
//     }

//     // Results from Lit and Auditor keygen() can be combined to create keyshares
//     async keygen () {
//       await init();
//       return rust.auditorKeygen(this.seed);
//     }

//     async pubkey (litKeygenForMe) {
//       await init();
//       return rust.auditorPubkeyShare(this.seed, litKeygenForMe); 
//     }
    
//     async decrypt (litKeygenForMe, encrypted, litPartialDecryption) {
//       await init();
//       let decrypted = rust.auditorDecrypt(this.seed, litKeygenForMe, encrypted, litPartialDecryption);
//       return rust.pointToMsg(decrypted);
//     }

// }

// class Encryption {
//     constructor(litPubkey, auditorPubkey) {
//         this.toPubkey = rust.sharedPubkey([litPubkey, auditorPubkey]);
//     }

//     // msg is a string
//     async encrypt(msg) {
//         await init();
//         const pt = rust.msgToPoint(msg);
//         // Nonce should be 64 bytes for optimal randomness. However, it probably doesn't matter
//         const nonce = BigInt("0x"+randomBytes(64).toString("hex")).toString();
//         return {
//             message: msg,
//             messageAsPoint: pt,
//             encrypted: rust.encryptPoint(pt, await this.toPubkey, nonce)
//         }
//     }
    
// }


// module.exports = {
//     init: init,
//     Auditor: Auditor,
//     Lit: Lit,
//     Encryption: Encryption,
// }