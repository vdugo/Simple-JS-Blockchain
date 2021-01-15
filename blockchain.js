const { sign } = require("crypto");
const SHA256 = require("crypto-js/sha256")
const EC = require("elliptic").ec;
const ec = new EC("secp256k1");



class Transaction
{
    /** A user will need to sign their transaction
    * with their private key. The class will also
    * be responsible for making sure that each 
    * transaction is valid.
    * @param {string} fromAddress 
    * @param {string} toAddress
    * @param {number} amount
    */
    constructor(fromAddress, toAddress, amount)
    {
        this.fromAddress = fromAddress;
        this.toAddress = toAddress;
        this.amount = amount;
    }

    /**
    * Calculates the SHA256 hash of a transaction
    * @returns {string}
    */
    calculateHash()
    {
        return SHA256(this.fromAddress + this.toAddress + this.amount).toString();
    }
    
    /**
     * Checks if the fromAddress is equal to the 
     * public key then signs the transaction with
     * the private key. You can only spend coins 
     * from wallets which you have the private key,
     *  because your private key and public key 
     * are mathematically linked. 
     * @param {string} signingKey 
     */
    signTransaction(signingKey)
    {
        if(signingKey.getPublic("hex") !== this.fromAddress)
        {
            throw new Error("You cannot sign transactions for other wallets, only your own.");
        }
        const hashTx = this.calculateHash();
        const sig = signingKey.sign(hashTx, "base64");
        this.signature = sig.toDER("hex");
    }

    /*
    function to verify if our transaction has been correctly
    signed. The one special transaction that we must take into
    account is our mining rewards. Because there is no fromAddress
    for mining rewards, this special case is a valid transaction and
    must be accounted for. A mining reward is a transaction that 
    goes from the null address to the mining reward address.
    */
    isValid()
    {
        // the transaction is valid if it is a mining reward
        if(this.fromAddress === null)
        {
            return true;
        }

        // otherwise the fromAddress is filled in, perform more checks

        // if there is no signature or the signature is empty
        if(!this.signature || this.signature.length === 0)
        {
            throw new Error("No signature in this transaction");
        }

        /*
        If we make it here, then that means that the transaction
        is not from the null address and it has a signature. Now
        we must verify that the transaction was signed with the
        correct key.
        */

        /*
        Create the public key using the fromAddress. Then verify
        that the hash of this block has been signed by the correct
        signature. This is done without needing the user's private
        key because their public and private keys are mathematically
        linked.
        */
        const publicKey = ec.keyFromPublic(this.fromAddress, "hex");

        return publicKey.verify(this.calculateHash(), this.signature);
    }
}

class Block
{
    /*
    timestamp will tell us when the block was created
    transactions is the transaction data in a block
    previousHash is a string that contains the previous block's hash
    hash will contain the hash of the block
    nonce is a value that is used to get a different hash after each
    proof of work calculation, this is needed because if nothing in a block
    is changed, then it will produce the same hash as before.
    */
    constructor(timestamp, transactions, previousHash = '')
    {
        this.timestamp = timestamp;
        this.transactions = transactions;
        this.previousHash = previousHash;
        this.hash = this.calculateHash();
        this.nonce = 0;
    }

    /*
    This function will take the properties of the block and run it through
    the SHA256 (secure hashing algorithm 256 bit) algorithm. After, it will
    return the hash of this block. This hash will be used to identify the
    block on the blockchain
    */
    calculateHash()
    {
        return SHA256(this.index + this.timestamp + this.previousHash + JSON.stringify(this.data) + this.nonce).toString();
    }

    /*
    Because we do not want people to create massive amounts of blocks per second,
    we need to implement proof of work (mining). Implementing proof of work also prevents
    someone from recalculating all of the hashes, creating a valid blockchain
    which was tampered with. We will make the hash of our newly mined block begin with
    an amount of zeroes equal to the mining difficulty.
    */
    mineBlock(difficulty)
    {
        /*
        We will attempt to make the first difficulty characters of the hash begin
        with 0's. This is done by recalculating the hash until the desired hash
        is achieved. Because calculating the hash of the same data will yield the same
        hash, we use a nonce value to change it with each iteration of the while loop,
        as changing the input of the hash function even slightly will greatly change
        the hash output. Take a substring of our hash from character 0 to difficulty,
        keep repeating the while loop while this part of the hash is not equal to the
        correct amount of zeroes. Loop stops once the desired number of zeroes is 
        achieved, thus successfully mining the block.
        */
        // the second part of the while condition creates a new array that is the same
        // length as the difficulty
        while(this.hash.substring(0, difficulty) !== Array(difficulty + 1).join("0"))
        {
            this.nonce++;
            this.hash = this.calculateHash();
        }
        console.log("Block mined: " + this.hash);
    }

    /*
    Checks if all of the transactions in the block are valid
    if there is even one that is invalid, then the entire block
    is invalid. Loops through every transaction in a block.
    */
   hasValidTransactions()
   {
       for(const tx of this.transactions)
       {
           if(!tx.isValid())
           {
               return false;
           }
       }
       // if we make it here then every transaction in the block is valid.
       return true;
   }
}

class Blockchain
{
    /* 
    chain is an array of blocks
    pendingTransactions is an array of blocks in queue to be processed
    the constructor creates the chain and pushes the genesis block onto it
    the mining difficulty is also arbitrarily set.
    mining reward is arbitrary, but halves every 4 years on the Bitcoin blockchain
    */
    constructor()
    {
        this.chain = [this.createGenesisBlock()];
        this.difficulty = 2;
        this.pendingTransactions = [];
        this.miningReward = 100;
    }

    /* 
    the first block on a blockchain is called the genesis block, this is
    the only block which does not have a previousHash or previous block that
    it points to, so we need to add the genesis block manually via the 
    constructor whenever a Blockchain object is instantiated
    */
    createGenesisBlock()
    {
        return new Block("01/01/2020", "Genesis block", "0");
    }

    /* 
    returns the latest block in the blockchain, the last index
    */
    getLatestBlock()
    {
        return this.chain[this.chain.length - 1];
    }

    /* deprecated function
    adds a new block onto the chain. First sets the previousHash
    of the new block to the hash of the latest block in the blockchain,
    that is, the block at the last index in the array, then it will 
    mine a new block by recalculating its hash because every time a 
    property in a block is changed, the hash must be recalculated. 
    Lastly, push the new block onto the blockchain.
    */
    //addBlock(newBlock)
    //{
    //    newBlock.previousHash = this.getLatestBlock().hash;
    //   newBlock.mineBlock(this.difficulty);
    //    this.chain.push(newBlock);
    //}

    /*
    Processes all the pending transactions, in a real blockchain
    the miners would choose which block to process next, as there
    would be far too many. This is simplified for demonstration
    purposes. We need pending transactions for security purposes.
    For example, the Bitcoin protocol has a fixed interval of 10
    minutes per block to be mined. Even if the amount of miners
    increases, the difficulty is automatically adjusted to achieve
    a 10 minute block time.
    miningRewardAddress is the address to send the mining reward to
    */
   minePendingTransactions(miningRewardAddress)
   {
       const rewardTx = new Transaction(null, miningRewardAddress, this.miningReward);
       this.pendingTransactions.push(rewardTx);

       let block = new Block(Date.now(), this.pendingTransactions);
       block.mineBlock(this.difficulty);

       console.log("Block successfully mined");
       this.chain.push(block);
       // reset the pending transactions and pay the miner simultaneously
       this.pendingTransactions = [ new Transaction(null, miningRewardAddress, this.miningReward) ]
   }

   /*
   Pushes a transaction onto the array of pending transactions
   */
   addTransaction(transaction)
   {
       // check if the fromAddress and toAddress are filled in
       if(!transaction.fromAddress || !transaction.toAddress)
       {
            throw new Error("Transaction must include from and to address");
       }

       // verify that the transaction we want to add is valid
       if(!transaction.isValid())
       {
           throw new Error("Cannot add invalid transaction to the chain");
       }

       this.pendingTransactions.push(transaction);
   }

   /*
   Gets the balance of the address given, this is obtained by looping 
   through every block's transactions of every block on the blockchain.
   Logically, whenever you are the from fromAddress, that means that
   you were the sender in the found transaction, so the money is subracted
   from your balance. Similarly, whenever you are the toAddress, that means
   that you were the receiver in the found transaction, so the money is
   added to your balance.
   */
   getBalanceOfAddress(address)
   {
       let balance = 0;

       for (const block of this.chain)
       {
           for (const trans of block.transactions)
           {
               if (trans.fromAddress === address)
               {
                   balance -= trans.amount;
               }

               if(trans.toAddress === address)
               {
                   balance += trans.amount;
               }
           }
       }

       return balance;
   }

    /*
    this function will check if the blockchain is valid. Whenever a new
    block is added, it cannot be changed without causing invalidation down
    the blockchain, because each block's hash is calculated using the its
    properties and the previous block's hash.
    */
    isChainValid()
    {
        // Check if the Genesis block hasn't been tampered with by comparing
        // the output of createGenesisBlock with the first block on our chain
        const realGenesis = JSON.stringify(this.createGenesisBlock());

        if (realGenesis !== JSON.stringify(this.chain[0])) 
        {
        return false;
        }
        
        // start looping at block 1, because block 0 is the genesis block
        for (let i = 1; i < this.chain.length; ++i)
        {
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i-1];

            // check if the current block has all valid transactions
            // if it doesn't then the blockchain is invalid
            if(!currentBlock.hasValidTransactions())
            {
                return false;
            }

            // check if the has of the current block is not equal to its hash calculation
            if (currentBlock.hash !== currentBlock.calculateHash())
            {
                // the blockchain is invalid if it doesn't match
                return false;
            }

            /* 
            check if our block points to a correct previous block.
            if the previous hash of the current block is not equal to
            the previous block's hash
            */
            if (currentBlock.previousHash !== previousBlock.hash)
            {
                return false;
            }
        }

        // if the loop finishes successfully without returning false, then
        // our blockchain is valid and not hacked

        return true;
        
    }
}

module.exports.Blockchain = Blockchain;
module.exports.Transaction = Transaction;
