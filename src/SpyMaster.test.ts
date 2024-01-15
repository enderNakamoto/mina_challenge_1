import {
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  MerkleMap,
  Poseidon,
  MerkleMapWitness
} from 'o1js';

import { SpyMaster } from './SpyMaster';
import { Constants } from './consts';

let proofsEnabled = false;

function initializeSpy(){
  const spyPrivate = PrivateKey.random();
  const spy = PublicKey.fromPrivateKey(spyPrivate)
  return Poseidon.hash(spy.toFields());
}

describe('SpyMaster Contract', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkAppInstance: SpyMaster,
    nullifierMap: MerkleMap,
    messageMap: MerkleMap,
    txn;

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

    // initialize the MerkleMaps
    nullifierMap = new MerkleMap();
    messageMap = new MerkleMap();

    // deploy the zkApp and initialize the MerkleMaps
    await localDeployAndInitMap();
  });

  async function localDeployAndInitMap() {
    // deploy the zkApp
     txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkAppInstance.deploy();
      zkAppInstance.initMapRoots(nullifierMap.getRoot(), messageMap.getRoot());
    });
    await txn.prove();

    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  it('sets intitial values as expected', () => {
    const numberOfMessages = zkAppInstance.numMessages.get();
    expect(numberOfMessages).toEqual(Field(0));

    const numberOfAddresses = zkAppInstance.numAddresses.get();
    expect(numberOfAddresses).toEqual(Field(0));

    const nullifierRoot = zkAppInstance.nullifierRoot.get();
    expect(nullifierRoot).toEqual(nullifierMap.getRoot());

    const messageRoot = zkAppInstance.messageRoot.get();
    expect(messageRoot).toEqual(messageMap.getRoot());
  });

  it ('can add new accounts to whitelist', async () => {
    let spyKey, nullifierRoot, numAddresses, spyWitness: MerkleMapWitness;

     // ----- Adding First Spy to whitelist ---- 
    spyKey = initializeSpy();
    spyWitness = nullifierMap.getWitness(spyKey);

    nullifierMap.set(spyKey, Constants.WHITELISTED_VALUE);

    txn = await Mina.transaction(senderAccount, () => {
      zkAppInstance.addEligibleAddress(spyWitness);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    // root state changed correctly after adding new address
    nullifierRoot = zkAppInstance.nullifierRoot.get();
    expect(nullifierRoot).toEqual(nullifierMap.getRoot());

    // numAddresses incremented correctly
    numAddresses = zkAppInstance.numAddresses.get();
    expect(numAddresses).toEqual(Field(1));

    // ----- Adding Second Spy to whitelist ---- 

    spyKey = initializeSpy();
    spyWitness = nullifierMap.getWitness(spyKey);

    nullifierMap.set(spyKey, Constants.WHITELISTED_VALUE);

    txn = await Mina.transaction(senderAccount, () => {
      zkAppInstance.addEligibleAddress(spyWitness);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    // root state changed correctly after adding new address
    nullifierRoot = zkAppInstance.nullifierRoot.get();
    expect(nullifierRoot).toEqual(nullifierMap.getRoot());

    // numAddresses incremented correctly
    numAddresses = zkAppInstance.numAddresses.get();
    expect(numAddresses).toEqual(Field(2));
  });

  it ('cannot add an already whitelisted account to whitelist', async () => {
    let spyKey, nullifierRoot, numAddresses, spyWitness: MerkleMapWitness;
      
    spyKey = initializeSpy();
    spyWitness = nullifierMap.getWitness(spyKey);

    nullifierMap.set(spyKey, Constants.WHITELISTED_VALUE);
    const rootAFterFirstAdd = nullifierMap.getRoot();
    
    txn = await Mina.transaction(senderAccount, () => {
      zkAppInstance.addEligibleAddress(spyWitness);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    expect(async () => {
       txn = await Mina.transaction(senderAccount, () => {
        zkAppInstance.addEligibleAddress(spyWitness);
      });
    }).rejects.toThrow(Constants.ALREADY_WHITELISTED_ERROR);
    
    // root state changed correctly after adding new address
    nullifierRoot = zkAppInstance.nullifierRoot.get();
    expect(nullifierRoot).toEqual(rootAFterFirstAdd);

    // numAddresses incremented correctly
    numAddresses = zkAppInstance.numAddresses.get();
    expect(numAddresses).toEqual(Field(1));
  });

  it ('cannot add messages to non whitelisted addresses', async () => {
      let spyKey: Field, spyMessage: Field, spyNullifierWitness: MerkleMapWitness, spyMessageWitness: MerkleMapWitness;

    spyKey = initializeSpy();
    spyNullifierWitness = nullifierMap.getWitness(spyKey);
    spyMessageWitness = messageMap.getWitness(spyKey);
    spyMessage = Field(123);

    expect(async () => {
      txn = await Mina.transaction(senderAccount, () => {
       zkAppInstance.updateMessages(
        spyNullifierWitness, 
        spyMessageWitness, 
        spyMessage
      );
     });
    }).rejects.toThrow(Constants.SPY_CANNOT_SET_MESSAGE_ERROR);
  });

  it ('can only add messages to whitelisted addresses', async () => {
    let spyKey: Field, spyNullifierWitness: MerkleMapWitness, spyMessageWitness: MerkleMapWitness;

    const spyMessage = Field(123);

    spyKey = initializeSpy();
    spyNullifierWitness = nullifierMap.getWitness(spyKey);
    spyMessageWitness = messageMap.getWitness(spyKey);
    messageMap.set(spyKey, spyMessage);

    // ----- Adding Spy to whitelist ----
    txn = await Mina.transaction(senderAccount, () => {
      zkAppInstance.addEligibleAddress(spyNullifierWitness);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    // one spy added in whitelist   
    let numAddresses = zkAppInstance.numAddresses.get();
    expect(numAddresses).toEqual(Field(1));

    // ----- Adding message to spy in whitelist ----
    txn = await Mina.transaction(senderAccount, () => {
      zkAppInstance.updateMessages(
        spyNullifierWitness, 
        spyMessageWitness, 
        spyMessage
      );
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    // message root state changed correctly after adding new message
    const messageRoot = zkAppInstance.messageRoot.get();
    expect(messageRoot).toEqual(messageMap.getRoot());

    // numMessages incremented correctly
    let numMessages = zkAppInstance.numMessages.get();
    expect(numMessages).toEqual(Field(1));
  });
});

