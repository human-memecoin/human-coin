const { 
    Connection, 
    Keypair, 
    PublicKey,
    sendAndConfirmTransaction,
    Transaction,
} = require('@solana/web3.js');
const { 
    Token,
    TOKEN_PROGRAM_ID,
    ASSOCIATED_TOKEN_PROGRAM_ID,
} = require('@solana/spl-token');
const { Metadata } = require('@metaplex-foundation/mpl-token-metadata');
require('dotenv').config();

async function createToken() {
    // Connect to cluster
    const connection = new Connection(process.env.SOLANA_RPC_URL, 'confirmed');
    
    // Generate a new wallet keypair
    const payer = Keypair.fromSecretKey(
        Buffer.from(JSON.parse(process.env.WALLET_PRIVATE_KEY))
    );

    // Generate a new keypair for token mint
    const mintAuthority = payer;
    const freezeAuthority = null; // No freeze authority
    const decimals = 9;

    try {
        // Create token mint
        const mint = await Token.createMint(
            connection,
            payer,
            mintAuthority.publicKey,
            freezeAuthority,
            decimals,
            TOKEN_PROGRAM_ID
        );

        console.log('Token created successfully!');
        console.log('Token address:', mint.publicKey.toString());

        // Create metadata
        const name = "HUMAN";
        const symbol = "HUMAN";
        const uri = ""; // Add your metadata URI here if you have one

        const metadataAccount = await Metadata.create({
            connection,
            mint: mint.publicKey,
            mintAuthority: payer,
            name,
            symbol,
            uri,
            sellerFeeBasisPoints: 0,
            creators: null,
            updateAuthority: payer.publicKey,
            isMutable: true,
        });

        console.log('Metadata created:', metadataAccount.toString());

        // Create associated token account
        const tokenAccount = await mint.getOrCreateAssociatedAccountInfo(
            payer.publicKey
        );

        console.log('Token account created:', tokenAccount.address.toString());

        // Mint initial supply (8.2 billion tokens)
        const initialSupply = 8_200_000_000;
        const supply = initialSupply * Math.pow(10, decimals);
        
        await mint.mintTo(
            tokenAccount.address,
            mintAuthority.publicKey,
            [],
            supply
        );

        console.log(`Minted ${initialSupply} tokens to:`, tokenAccount.address.toString());

        // Optional: Disable future minting
        // await mint.setAuthority(
        //     mint.publicKey,
        //     null,
        //     'MintTokens',
        //     mintAuthority.publicKey,
        //     []
        // );
        // console.log('Minting disabled');

    } catch (error) {
        console.error('Error creating token:', error);
    }
}

createToken().then(() => process.exit());
