const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("Deploying DocumentRegistry contract...");

  const DocumentRegistry = await hre.ethers.getContractFactory("DocumentRegistry");
  const contract = await DocumentRegistry.deploy();

  await contract.waitForDeployment();
  const address = await contract.getAddress();

  console.log(`DocumentRegistry deployed to: ${address}`);

  // Write ABI to Python service
  const artifactsDir = path.join(__dirname, "../artifacts/contracts/DocumentRegistry.sol/DocumentRegistry.json");
  const artifact = require(artifactsDir);
  
  const abiDest = path.join(__dirname, "../../app/services/contract_abi.json");
  fs.writeFileSync(abiDest, JSON.stringify(artifact.abi, null, 2));
  
  console.log(`ABI exported to: ${abiDest}`);
  console.log("\nMake sure to update CONTRACT_ADDRESS in your .env file!");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
