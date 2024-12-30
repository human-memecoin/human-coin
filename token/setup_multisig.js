const { 
    Connection, 
    Keypair, 
    PublicKey,
    Transaction,
    sendAndConfirmTransaction,
} = require('@solana/web3.js');
const { Token } = require('@solana/spl-token');
require('dotenv').config();

async function setupMultisig() {
    // Connect to cluster
    const connection = new Connection(process.env.SOLANA_RPC_URL, 'confirmed');
    
    // Load your wallet
    const payer = Keypair.fromSecretKey(
        Buffer.from(JSON.parse(process.env.WALLET_PRIVATE_KEY))
    );

    // Create multisig with m/n configuration
    const m = 2; // Number of signatures required
    const n = 3; // Number of signers

    try {
        // Create the multisig
        const multisigKeypair = Keypair.generate();
        
        // Initialize multisig account
        // Note: In production, you would use a proper multisig program like Squads
        console.log('Multisig address:', multisigKeypair.publicKey.toString());
        
        // Transfer mint authority
        const token = new Token(
            connection,
            new PublicKey(process.env.TOKEN_ADDRESS),
            TOKEN_PROGRAM_ID,
            payer
        );

        await token.setAuthority(
            token.publicKey,
            multisigKeypair.publicKey,
            'MintTokens',
            payer.publicKey,
            []
        );

        console.log('Mint authority transferred to multisig');
        
        return multisigKeypair.publicKey;
    } catch (error) {
        console.error('Error setting up multisig:', error);
        throw error;
    }
}

setupMultisig().catch(console.error);
