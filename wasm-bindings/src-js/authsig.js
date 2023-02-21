const { ethers } = require("ethers");
const { SiweMessage } = require("siwe");
const { fromString } = require("uint8arrays");
require("dotenv").config();

const constructAuthsig = async () => {
    const privKey = process.env.LIT_ACTION_DEPLOYER_PRIVATE_KEY.replace("0x","");
    const privKeyBuffer = fromString(privKey, "base16");
    const wallet = new ethers.Wallet(privKeyBuffer);

    const domain = "localhost";
    const origin = "https://localhost/login";
    const statement =
    "This is a test statement.  You can put anything you want here.";
    const siweMessage = new SiweMessage({
    domain,
    address: wallet.address,
    statement,
    uri: origin,
    version: "1",
    chainId: "1",
    });

    const messageToSign = siweMessage.prepareMessage();

    const signature = await wallet.signMessage(messageToSign);

    // console.log("signature", signature);

    const recoveredAddress = ethers.utils.verifyMessage(messageToSign, signature);

    const authSig = {
    sig: signature,
    derivedVia: "web3.eth.personal.sign",
    signedMessage: messageToSign,
    address: recoveredAddress,
    };

    return authSig;
}

constructAuthsig();

module.exports = {
    constructAuthsig: constructAuthsig
}