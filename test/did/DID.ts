import { expect } from 'chai';
import { ethers } from 'hardhat';

import { createInstances } from '../instance';
import { getSigners, initSigners } from '../signers';
import { deployDIDFixture } from './DID.fixture';
import { getToken } from './token';

describe('DecentralizedId', function () {
  before(async function () {
    await initSigners(3);
    this.signers = await getSigners();
  });

  beforeEach(async function () {
    const contract = await deployDIDFixture();
    this.contractAddress = await contract.getAddress();
    this.did = contract;
    this.instances = await createInstances(this.contractAddress, ethers, this.signers);
  });

  it('should add identifier', async function () {
    const bobDid = 'did:zama:0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

    const encryptedBirth = this.instances.alice.encrypt32(495873907);
    const tx1 = await this.did.registerDID(this.signers.bob.address, bobDid);
    await tx1.wait();
    const transaction = await this.did['setIdentifier(string,string,bytes)'](bobDid, 'birthdate', encryptedBirth);
    await transaction.wait();

    // Bob sign a token to give access to Carol
    const provider = ethers.provider;
    const network = await provider.getNetwork();
    const chainId = +network.chainId.toString(); // Need to be a number
    const bobToken = getToken(chainId, this.contractAddress, 'birthdate', this.signers.carol.address);
    const bobSignature = await this.signers.bob.signTypedData(bobToken.domain, bobToken.types, bobToken.message);

    // Carol use this token to access information
    const token = this.instances.carol.getTokenSignature(this.contractAddress) || {
      signature: '',
      publicKey: '',
    };

    const encryptedBirthdate = await this.did
      .connect(this.signers.carol)
      .getIdentifier(bobDid, 'birthdate', bobSignature, token.publicKey, token.signature);
    const birthdate = this.instances.carol.decrypt(this.contractAddress, encryptedBirthdate);

    expect(birthdate).to.be.equal(495873907);
  });
});
