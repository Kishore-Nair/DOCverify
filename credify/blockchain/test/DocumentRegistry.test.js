const { expect } = require("chai");
const hre = require("hardhat");

describe("DocumentRegistry", function () {
  let DocumentRegistry;
  let registry;
  let owner;
  let addr1;
  let addr2;

  const docHash = hre.ethers.keccak256(hre.ethers.toUtf8Bytes("test-document"));
  const ipfsCid = "QmTestCid123";

  beforeEach(async function () {
    DocumentRegistry = await hre.ethers.getContractFactory("DocumentRegistry");
    [owner, addr1, addr2] = await hre.ethers.getSigners();
    registry = await DocumentRegistry.deploy();
    await registry.waitForDeployment();
  });

  it("Should store a new document", async function () {
    await expect(registry.storeDocument(docHash, ipfsCid))
      .to.emit(registry, "DocumentStored");

    const doc = await registry.verifyDocument(docHash);
    expect(doc.exists).to.equal(true);
    expect(doc.ipfsCid).to.equal(ipfsCid);
    expect(doc.revoked).to.equal(false);
  });

  it("Should not store a duplicate document", async function () {
    await registry.storeDocument(docHash, ipfsCid);
    await expect(registry.storeDocument(docHash, "QmAnother")).to.be.revertedWith("Document already registered");
  });

  it("Should revoke an existing document", async function () {
    await registry.storeDocument(docHash, ipfsCid);
    await expect(registry.revokeDocument(docHash))
      .to.emit(registry, "DocumentRevoked");

    const doc = await registry.verifyDocument(docHash);
    expect(doc.revoked).to.equal(true);
  });

  it("Should not allow non-owners to revoke", async function () {
    await registry.storeDocument(docHash, ipfsCid);
    await expect(registry.connect(addr1).revokeDocument(docHash)).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
  });
});
