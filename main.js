/*
Simple implementation of a blockchain in Javascript
for demonstration purposes.
*/

const {Blockchain, Transaction} = require("./blockchain");
const EC = require("elliptic").ec;
const ec = new EC("secp256k1");

// initialize our key using one of the private keys generated in keygenerator.js
const myKey = ec.keyFromPrivate("98d0968702a152172e0918bfc21e5b98d235d157cd06e4751b15f018dccb0022");
// get our wallet address (which is our public key) from the private key
const myWalletAddress = myKey.getPublic("hex");

let blockchain = new Blockchain();

// sending 5 coins from my wallet to someone else's
const tx1 = new Transaction(myWalletAddress, "someone else's wallet address goes here", 5);
// sign the transaction with my key
tx1.signTransaction(myKey);

// push the transaction onto the blockchain
blockchain.addTransaction(tx1);

console.log("Starting the miner...");
// mining reward will go to my wallet
blockchain.minePendingTransactions(myWalletAddress);

console.log("Your current balance is: " + blockchain.getBalanceOfAddress(myWalletAddress));

console.log("Is chain valid? " + blockchain.isChainValid());

/**
 * does something
 * @
 */
