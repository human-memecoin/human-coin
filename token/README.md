# Human Coin Token Contract

This directory contains the Human Coin (HUMAN) token contract for Solana blockchain.

## Token Details
- Name: Human Coin
- Symbol: HUMAN
- Decimals: 9 (standard for Solana)
- Initial Supply: 1,000,000,000 (1 billion)
- Network: Solana

## Development Setup
1. Install Solana CLI tools
2. Install Rust and Cargo
3. Install Anchor framework

## Commands
```bash
# Create new token
solana-keygen new -o token-keypair.json
spl-token create-token token-keypair.json

# Create token account
spl-token create-account <token-address>

# Mint tokens
spl-token mint <token-address> <amount> <recipient-address>

# Transfer tokens
spl-token transfer <token-address> <amount> <recipient-address>
```

## Security
- Mint authority: Controlled by multisig
- Freeze authority: None
- Transfer fees: None
