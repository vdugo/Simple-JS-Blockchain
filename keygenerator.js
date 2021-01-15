/*
import the elliptic curve library to generate our private/public key pairs
*/
const EC = require("elliptic").ec;

// create a new elliptic curve object using secp256k1, the same algorithm that bitcoin uses
const ec = new EC("secp256k1");

// generate a new key pair then convert them to hexdecimal strings
const key = ec.genKeyPair();

const publicKey = key.getPublic("hex");
const privateKey = key.getPrivate("hex");

console.log();
console.log("(KEEP THIS SAFE LIKE YOUR PASSWORD) Private key generated: " + privateKey);
console.log("(also known as your wallet address) Public key generated: " + publicKey);

