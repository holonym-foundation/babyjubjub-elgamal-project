const { expect } = require("chai");
const { Auditor, Lit, Encryption  } = require("../src-js/wrapper");

describe("Encryption", function() {
    before(async function () {
        this.auditor = new Auditor(Buffer.from("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "hex"));
        this.lit = new Lit(Buffer.from("11112222333344444555566667777888899990000aaaabbbbccccddddeeeeffff", "hex"));
        this.auditorKeygenForLit = await this.auditor.keygen();
        this.litKeygenForAuditor = await this.lit.keygen();
        this.auditorPubkey = await this.auditor.pubkey(this.litKeygenForAuditor);
        this.litPubkey = await this.lit.pubkey(this.auditorKeygenForLit);
        this.encryption = new Encryption(this.litPubkey, this.auditorPubkey);
    });
    it("encrypt -> decrypt", async function() {
        const msg = 12345678901234567890n
        const encrypted = await this.encryption.encrypt(msg.toString());
        const litPartialDecryption = await this.lit.partialDecrypt(this.auditorKeygenForLit, encrypted.encrypted.c1);
        const fullDecryption = await this.auditor.decrypt(this.litKeygenForAuditor, encrypted.encrypted, litPartialDecryption);
        expect(msg.toString()).to.equal(fullDecryption);
    })
});