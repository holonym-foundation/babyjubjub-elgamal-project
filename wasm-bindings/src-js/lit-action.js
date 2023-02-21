const { ethers, Wallet } = require("ethers");
// This soon deprecated:
const LitJsSdk = require("lit-js-sdk");
const { constructAuthsig } = require("./authsig.js");
// Instead use this:
// import * as LitJsSdk from "@lit-protocol/lit-node-client";
require("dotenv").config();

const code = `const go = async () => {
    // this is the string "Hello World" for testing
    const toSign = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
    // this requests a signature share from the Lit Node
    // the signature share will be automatically returned in the HTTP response from the node
    const sigShare = await Lit.Actions.signEcdsa({
      toSign,
      publicKey:
        "0x04ea2311963bd543e9817b4ad1e7bf8185d42e26a2668d31097cd860ef70a5929322eb4e7a5fe2bf9721c11927dd1317d9267e8320b92f388ac7441368bc91db0d",
      sigName: "sig1",
    });
  };
  
  go();`

  // const constructAuthsig = async () => {
  //   const w = new Wallet(process.env.LIT_ACTION_DEPLOYER_PRIVATE_KEY);
  //   const toSign = `localhost wants you to sign in with your Ethereum account:\n${w.address}`
  //   const signed =  await w.signMessage(toSign);
  //   return {
  //       sig: signed,
  //       derivedVia: "web3.eth.personal.sign", //"ethers.Wallet.signMessage",
  //       signedMessage: toSign,
  //       address: w.address
  //   }
  // }
  

  const chain = "ethereum";

  const unifiedAccessControlConditions = [
    {
      conditionType: "evmBasic",
      contractAddress: "",
      standardContractType: "",
      chain,
      method: "eth_getBalance",
      parameters: [":userAddress", "latest"],
      returnValueTest: {
        comparator: ">=",
        value: "0",
      },
    },
  ];
const run = async () => {
  const litNodeClient = new LitJsSdk.LitNodeClient({ litNetwork: "serrano", debug: true });
  await litNodeClient.connect();

  const authSig = await constructAuthsig();
  console.log("authsig", authSig)

  const results = await litNodeClient.executeJs({
    code,
    authSig,
    // jsParams: {
    //   unifiedAccessControlConditions,
    //   authsig,
    //   chain
    // }
  });
  // console.log("recieved", results);


}

run().then(x=>console.log(x))






// // this code will be run on the node
// const litActionCode = `
// const go = async () => {
//   // this requests a signature share from the Lit Node
//   // the signature share will be automatically returned in the response from the node
//   // and combined into a full signature by the LitJsSdk for you to use on the client
//   // all the params (toSign, publicKey, sigName) are passed in from the LitJsSdk.executeJs() function
//   const sigShare = await LitActions.signEcdsa({ toSign, publicKey, sigName });
// };
// go();
// `;

// you need an AuthSig to auth with the nodes
// normally you would obtain an AuthSig by calling LitJsSdk.checkAndSignAuthMessage({chain})
// const authSig = {
//   sig: "0x2bdede6164f56a601fc17a8a78327d28b54e87cf3fa20373fca1d73b804566736d76efe2dd79a4627870a50e66e1a9050ca333b6f98d9415d8bca424980611ca1c",
//   derivedVia: "web3.eth.personal.sign",
//   signedMessage:
//     "localhost wants you to sign in with your Ethereum account:\n0x9D1a5EC58232A894eBFcB5e466E3075b23101B89\n\nThis is a key for Partiful\n\nURI: https://localhost/login\nVersion: 1\nChain ID: 1\nNonce: 1LF00rraLO4f7ZSIt\nIssued At: 2022-06-03T05:59:09.959Z",
//   address: "0x9D1a5EC58232A894eBFcB5e466E3075b23101B89",
// };


// const runLitAction = async () => {
//   const authSig = await constructAuthsig("abcdefg")
//   console.log("authsig", authSig)
//   const litNodeClient = new LitJsSdk.LitNodeClient({
//     alertWhenUnauthorized: false,
//     litNetwork: "serrano",
//     debug: true,
//   });
//   await litNodeClient.connect();
//   const results = await litNodeClient.executeJs({
//     code: litActionCode,
//     authSig,
//     // all jsParams can be used anywhere in your litActionCode
//     jsParams: {
//       // this is the string "Hello World" for testing
//       toSign: [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100],
//       publicKey:
//         "0x0404e12210c57f81617918a5b783e51b6133790eb28a79f141df22519fb97977d2a681cc047f9f1a9b533df480eb2d816fb36606bd7c716e71a179efd53d2a55d1",
//       sigName: "sig1",
//     },
//   });
//   console.log("results: ", results);
// };

// runLitAction();