// This is gold https://stackoverflow.com/a/71673305/14039774
import init, { enableErrors, auditorKeygen, auditorDecrypt, litKeygen, litDecrypt, msgToPoint, pointToMsg, litPubkeyShare, auditorPubkeyShare, sharedPubkey, node_from_seed, random_node, read_node, encryptPoint } from '../bindings/elgamal_babyjubjub';
import wasmData from '../bindings/elgamal_babyjubjub_bg.wasm';
const { randomBytes } = require("crypto");
// console.log(Buffer.from(wasmData))
let loaded = false;
let rust = init(wasmData);

async function waitTilLoaded () {
  if(loaded) {
    return 
  } else {
    await rust;
    loaded = true;
  }
}

export class Lit {
    // Seed is a U8Array / Buffer
    constructor(seed) {
        this.seed = seed;
    }

    // Results from Lit and Auditor keygen can be combined to create keyshares
    async keygen () {
      await waitTilLoaded();
      return litKeygen(this.seed);
    }

    async pubkey (auditorKeygenForMe) {
        await waitTilLoaded();
        return litPubkeyShare(this.seed, auditorKeygenForMe); 
    }
    
    async partialDecrypt (auditorKeygenForMe, encrypted) {
        await waitTilLoaded();
        return litDecrypt(this.seed, auditorKeygenForMe, encrypted);
    }
    
}

export class Auditor {
    // Seed is a U8Array / Buffer
    constructor(seed) {
        this.seed = seed;
    }

    // Results from Lit and Auditor keygen() can be combined to create keyshares
    async keygen () {
      await waitTilLoaded();
      return auditorKeygen(this.seed);
    }

    async pubkey (litKeygenForMe) {
      await waitTilLoaded();
      return auditorPubkeyShare(this.seed, litKeygenForMe); 
    }
    
    async decrypt (litKeygenForMe, encrypted, litPartialDecryption) {
      await waitTilLoaded();
      let decrypted = auditorDecrypt(this.seed, litKeygenForMe, encrypted, litPartialDecryption);
      return pointToMsg(decrypted);
    }

}

export class Encryption {
    constructor(litPubkey, auditorPubkey) {
        this.toPubkey = sharedPubkey([litPubkey, auditorPubkey]);
    }

    // msg is a string
    async encrypt(msg) {
        await waitTilLoaded();
        const pt = msgToPoint(msg);
        // Nonce should be 64 bytes for optimal randomness. However, it probably doesn't matter
        const nonce = BigInt("0x"+randomBytes(64).toString("hex")).toString();
        return {
            message: msg,
            messageAsPoint: pt,
            encrypted: encryptPoint(pt, await this.toPubkey, nonce)
        }
    }
}

export class Utils {
  static async msgToPoint(msg) {
    await waitTilLoaded();
    return msgToPoint(msg);
  }

  static async pointToMsg(pt) {
    await waitTilLoaded();
    return msgToPoint(msg);
  }
}