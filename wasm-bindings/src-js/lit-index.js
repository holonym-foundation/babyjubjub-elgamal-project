const { Auditor, Lit, Encryption } = require("./wrapper");

const litSeed = Buffer.from("66667777888844444555566669999888899990000aaaabbbbccccddddeeee1234", "hex");
const keygenHelper = {
    for_node: 1,
    value: [
        1,
        [
            586699427, 1543367276,
            10925331, 4170191634,
            2689585544,  460502168,
            1845382881,    9894354
        ]
    ]
}

const l = new Lit(litSeed);
l.pubkey(keygenHelper).then(x=>console.log(x));