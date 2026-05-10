# Credify Blockchain Subproject

This is a Hardhat project for the Credify document registry smart contract.

## Setup

```sh
npm install
```

## Running a Local Node

Start a local Hardhat node (RPC at `http://127.0.0.1:8545`):

```sh
npx hardhat node
```

## Compiling & Testing

In a new terminal window:

```sh
npx hardhat compile
npx hardhat test
```

## Deployment

To deploy the contract to the local node:

```sh
npx hardhat run scripts/deploy.js --network localhost
```

This will deploy the contract, print its address, and export the ABI directly to `../app/services/contract_abi.json` for the Python backend to use. You must then copy the deployed contract address and set it in your `.env` file as `CONTRACT_ADDRESS`.
