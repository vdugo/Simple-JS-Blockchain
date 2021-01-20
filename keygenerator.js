// import file system to write the generated keys to a text file
const fs = require("fs");

// import the elliptic curve library to generate our private/public key pairs
const EC = require("elliptic").ec;

// create a new elliptic curve object using secp256k1, the same algorithm that bitcoin uses
const ec = new EC("secp256k1");

// generate a new key pair then convert them to hexdecimal strings
const key = ec.genKeyPair();

const publicKey = key.getPublic("hex");
const privateKey = key.getPrivate("hex");

// make a string with publicKey on the first line then privateKey on the next
const keys = publicKey + "\n" + privateKey;

// write the generated keys to a text file
fs.writeFile("keys.txt", keys, (err) => {
    if (err) throw err;
});

console.log("Public and Private keys written to file \"keys.txt\"");
console.log("(also known as your wallet address) Public key generated: " + publicKey);
console.log("(KEEP THIS SAFE LIKE YOUR PASSWORD) Private key generated: " + privateKey);


