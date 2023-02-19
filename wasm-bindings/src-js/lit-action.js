const { ethers, Wallet } = require("ethers");
const LitJsSdk = require("lit-js-sdk");
require("dotenv").config();

const code = `const go = async () => {
    // this is the string "Hello World" for testing
    const toSign = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
    // this requests a signature share from the Lit Node
    // the signature share will be automatically returned in the HTTP response from the node
    const sigShare = await Lit.Actions.signEcdsa({
      toSign,
      publicKey:
        "0x0404e12210c57f81617918a5b783e51b6133790eb28a79f141df22519fb97977d2a681cc047f9f1a9b533df480eb2d816fb36606bd7c716e71a179efd53d2a55d1",
      sigName: "sig1",
    });
  };
  
  go();`

  const constructAuthsig = async (toSign) => {
    const w = new Wallet(process.env.LIT_ACTION_DEPLOYER_PRIVATE_KEY);
    const signed =  await w.signMessage(toSign);
    return {
        sig: signed,
        derivedVia: "web3.eth.personal.sign", //"ethers.Wallet.signMessage",
        signedMessage: toSign,
        address: w.address
    }
  }
  


  const run = async () => {
    const litNodeClient = new LitJsSdk.LitNodeClient({ litNetwork: "serrano" });
    // const authSig = await LitJsSdk.checkAndSignMessage
    const toSign = "this is a message that should be signed"
    await constructAuthsig(toSign);
    await litNodeClient.connect();
  }

  run.then(x=>console.log(x))