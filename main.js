/*
Simple implementation of a blockchain in Javascript
for demonstration purposes.
*/

const {Blockchain, Transaction} = require("./blockchain");
const EC = require("elliptic").ec;
const ec = new EC("secp256k1");

// initialize our key using one of the private keys generated in keygenerator.js
const myKey = ec.keyFromPrivate("5ef4b9aab8105a31e793a6b4eaf10a4b1f1f96bfb1450abc8e0facf9f65c8a03");
// get our wallet address (which is our public key) from the private key
const myWalletAddress = myKey.getPublic("hex");

let blockchain = new Blockchain();

console.log("Current mining reward per block is: " + blockchain.miningReward);

console.log("Sending 5 coins to someone else's wallet and receiving the mining reward myself:");
// sending 5 coins from my wallet to someone else's
const tx1 = new Transaction(myWalletAddress, "someone else's wallet address goes here", 5);
// sign the transaction with my key
tx1.signTransaction(myKey);

// push the transaction onto the blockchain
blockchain.addTransaction(tx1);

console.log("Starting the miner...");
// mining reward will go to my wallet
blockchain.minePendingTransactions(myWalletAddress);

console.log("My current balance is: " + blockchain.getBalanceOfAddress(myWalletAddress));

console.log("Is chain valid? " + blockchain.isChainValid());

console.log("Tampering with the first transaction:")

blockchain.chain[1].transactions[0].amount = 2;

console.log("Is the blockchain still valid after tampering?:" + blockchain.isChainValid());



