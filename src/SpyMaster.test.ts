import { SpyMaster } from './SpyMaster';

import {
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  MerkleMap,
  Poseidon
} from 'o1js';

let proofsEnabled = false;

describe('OdometerVerifier', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkAppInstance: SpyMaster,
    nullifierMap: MerkleMap,
    messageMap: MerkleMap;

  beforeAll(async () => {
    if (proofsEnabled) await SpyMaster.compile();
  });

  beforeEach( async () => {
    // set up a local blockchain
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);

    // Local.testAccounts is an array of 10 test accounts that have been pre-filled with Mina
    ({ privateKey: deployerKey, publicKey: deployerAccount } = Local.testAccounts[0]);
    ({ privateKey: senderKey, publicKey: senderAccount } = Local.testAccounts[1]);

    // create a zkApp account
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkAppInstance = new SpyMaster(zkAppAddress);

    // deploy the zkApp
    const txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkAppInstance.deploy();
    });

    await txn.prove();

    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  });

  it('sets intitial state of numMessages to 0', () => {
    const numberOfMessages = zkAppInstance.numMessages.get();
    expect(numberOfMessages).toEqual(Field(0));
  });

  it('sets intitial state of numAddresses to 0', () => {
    const numberOfAddresses = zkAppInstance.numAddresses.get();
    expect(numberOfAddresses).toEqual(Field(0));
  });

});
