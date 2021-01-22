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
        this.timestamp = Date.now();
    }

    /**
    * Creates the SHA256 hash of a transaction
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

    /** Function to verify if our transaction has been correctly
     * signed. The one special transaction that we must take into
     * account is the mining reward transaction. Despite there being
     * no fromAddress for mining rewards, this special case is still
     * considered a valid transaction and must be accounted for.
     * A mining reward is a transaction that goes from the null address
     * to the mining reward address.
     * @returns {boolean}
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
    /**
     * @param {number} timestamp
     * @param {Transaction[]} transactions
     * @param {string} previousHash
     */
    
    constructor(timestamp, transactions, previousHash = '')
    {
        /*
        nonce is a value that is used to get a different hash after each
        proof of work calculation, this is needed because if nothing in a block
        is changed, then it will produce the same hash as before.
        */
        this.timestamp = timestamp;
        this.transactions = transactions;
        this.previousHash = previousHash;
        this.hash = this.calculateHash();
        this.nonce = 0;
    }

    /**
     * Calculates the SHA256 hash of a block using all of its data
     * This hash will be used to identify the block on the blockchain.
     * @returns {string} 
    */
    calculateHash()
    {
        return SHA256(this.index + this.timestamp + this.previousHash + JSON.stringify(this.data) + this.nonce).toString();
    }

    /**
     * Begins mining a block. Changes the nonce until
     * the hash of the block is calculated with the amount
     * of zeroes equal to the mining difficulty. Because we
     * do not want people to create massive amounts of blocks per
     * second, we need to implement this proof of work (mining)
     * concept. Proof of work also prevents someone from recalculating
     * all of the hashes, which would create a valid blockchain despite
     * it being tampered with.
     * @param {number} difficulty 
     */
    mineBlock(difficulty)
    {
        /*
        Because calculating the hash of the same data will yield the same
        hash, we need a nonce value to change it with each iteration of the while loop,
        as changing the input of the hash function even slightly will greatly change
        the hash output. Take a substring of our hash from character 0 to difficulty,
        keep repeating the while loop while this part of the hash is not equal to the
        correct amount of zeroes. Loop stops once the desired number of zeroes is 
        achieved, thus successfully mining the block. The second part of the while condition
        creates a new array that is the same length as the difficulty.
        */
        while(this.hash.substring(0, difficulty) !== Array(difficulty + 1).join("0"))
        {
            this.nonce++;
            this.hash = this.calculateHash();
        }
        console.log("Block mined: " + this.hash);
    }

   /**
    * Validates all the transactions in the block. Returns
    * false if the block is invalid. Loops through every 
    * transaction in a block.
    * @returns {boolean}
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
   /**
    * The constructor creates the chain and automatically pushes the
    * genesis block onto it. Mining difficulty is arbitrarily set. On
    * the Bitcoin blockchain, the mining reward halves every 210,000 blocks
    * or approximately 4 years.
    * @param {Block[]} chain
    * @param {number} difficulty
    * @param {Array} pendingTransactions
    * @param {number} miningReward
    */
    constructor()
    {
        this.chain = [this.createGenesisBlock()];
        this.difficulty = 2;
        this.pendingTransactions = [];
        this.miningReward = 100;
    }

   /**
    * The first block on a blockchain is called the genesis block, this is
    * the only block which does not have a previousHash or previous block that
    * it can point to. We need to add the genesis block manually via the
    * constructor whenever a Blockchain object is instantiated.
    * @returns {Block}
    */
    createGenesisBlock()
    {
        return new Block("01/01/2020", "Genesis block", "0");
    }

   /**
    * Returns the latest block in the blockchain, which
    * is the last index. Good for when you need to create
    * a new Block and need the hash of the previous Block.
    * @returns {Block[]}
    */
    getLatestBlock()
    {
        return this.chain[this.chain.length - 1];
    }

    /**
     * Puts all the currently pending transactions into a Block
     * then starts the mining process. Also adds a transaction
     * for the mining reward, which is sent to the givern address.
     * In a real blockchain, miners would choose which block to
     * process next. Transactions must be pending for security purposes.
     * For example, the Bitcoin protocol has about a 10 minute block
     * mining time. Even if the amount of miners increases, the difficulty
     * would be automatically adjusted to achieve a 10 minute block time.
     * @param {string} miningRewardAddress 
     */
    minePendingTransactions(miningRewardAddress)
    {
       // create the reward transaction and push it onto the pending transactions 
       const rewardTx = new Transaction(null, miningRewardAddress, this.miningReward);
       this.pendingTransactions.push(rewardTx);
       
       // make a new block with the transactions currently in pending transactions then start mining
       let block = new Block(Date.now(), this.pendingTransactions);
       block.mineBlock(this.difficulty);
       
       // push the newly mined block onto the blockchain
       console.log("Block successfully mined");
       this.chain.push(block);
       
       // reset the pending transactions and pay the miner simultaneously
       this.pendingTransactions = [ new Transaction(null, miningRewardAddress, this.miningReward) ]
    }

   /**
    * Pushes a transaction onto the array of pending transactions.
    * Verifies that the given transaction is properly signed.
    * @param {Transaction} transaction 
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

   /**
    * Gets the balance of the address given. This is obtained
    * by looping through every block's transactions of every block
    * that is on the blockchain. Logically, whenever you are the
    * fromAddress, this means that you were the sender in the found
    * transaction, so the money is subtracted from your balance. Similarly,
    * whenever you are the toAddress, that means that you were the receiver
    * in the found transaction, so the money is added to your balance.
    * @param {string} address 
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

   /**
    * Checks if the blockchain is valid by looping over all the blocks
    * in the chain and verifying if they are properly linked together
    * and that no hashes have been tampered with. Consequently, all of
    * the transactions inside of the blocks are also verified.
    * @returns {boolean}
    */
    isChainValid()
    {
        /* 
        Check if the Genesis block hasn't been tampered with by comparing
        the output of createGenesisBlock with the first block on our chain
        */
        const realGenesis = JSON.stringify(this.createGenesisBlock());

        if (realGenesis !== JSON.stringify(this.chain[0])) 
        {
        return false;
        }
        
        /*
        Now check the rest of the blocks. Start looping at block 1, because
        block 0 is the genesis block.
        */
        for (let i = 1; i < this.chain.length; ++i)
        {
            const currentBlock = this.chain[i];
            const previousBlock = this.chain[i-1];

            /* 
            Check if the current block has all valid transactions.
            If it doesn't then the entire blockchain is invalid.
            */
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
        /* 
        If the loop finishes successfully without returning false,
        then our blockchain is valid and not hacked.
        */
        return true;
        
    }
}

module.exports.Blockchain = Blockchain;
module.exports.Block = Block;
module.exports.Transaction = Transaction;
