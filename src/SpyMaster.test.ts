import {
  Field,
  Bool,
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

const VALID_FLAG_MESSAGE = Field(449); // 1110_00001 - condition 1 will be true
const INVALID_FLAG_MESSAGE = Field(1539); // 11000_000011 - condition 1 and 2 will be false


function initializeSpy(){
  const spyPrivate = PrivateKey.random();
  return { 
    spyDigest: Poseidon.hash(spyPrivate.toPublicKey().toFields()),
    spykey: spyPrivate, 
    spyAccount: spyPrivate.toPublicKey()
  }
}

describe('SpyMaster Contract', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    notAdminAccount: PublicKey,
    notAdminKey: PrivateKey,
    spyOneAccount: PublicKey,
    spyOneKey: PrivateKey,
    spyTwoAccount: PublicKey,
    spyTwoKey: PrivateKey,
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
    ({ privateKey: notAdminKey, publicKey: notAdminAccount } = Local.testAccounts[2]);
    ({ privateKey: spyOneKey, publicKey: spyOneAccount } = Local.testAccounts[3]);
    ({ privateKey: spyTwoKey, publicKey: spyTwoAccount } = Local.testAccounts[4]);

    // create a zkApp account
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkAppInstance = new SpyMaster(zkAppAddress);

    // initialize the MerkleMaps
    nullifierMap = new MerkleMap();
    messageMap = new MerkleMap();

    // deploy the zkApp and initialize the MerkleMaps
    await localDeploy();
    await initializeVault();
  });

  async function localDeploy() {
    // deploy the zkApp
     txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkAppInstance.deploy();
      
    });
    await txn.prove();

    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  async function initializeVault() {
      txn = await Mina.transaction(senderAccount, () => {
        zkAppInstance.initializeState(nullifierMap.getRoot(), messageMap.getRoot());
      });
      await txn.prove();
      await txn.sign([senderKey]).send();
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
    let spy, spyKey, nullifierRoot, numAddresses, spyWitness: MerkleMapWitness;

     // ----- Adding First Spy to whitelist ---- 
    spy = initializeSpy();
    spyWitness = nullifierMap.getWitness(spy.spyDigest);

    nullifierMap.set(spy.spyDigest, Constants.WHITELISTED_VALUE);

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

    spy = initializeSpy();
    spyWitness = nullifierMap.getWitness(spy.spyDigest);

    nullifierMap.set(spy.spyDigest, Constants.WHITELISTED_VALUE);

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
    let spy, spyKey, nullifierRoot, numAddresses, spyWitness: MerkleMapWitness;
      
    spy = initializeSpy();
    spyWitness = nullifierMap.getWitness(spy.spyDigest);

    nullifierMap.set(spy.spyDigest, Constants.WHITELISTED_VALUE);
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
      let spy, spyKey: Field, spyNullifierWitness: MerkleMapWitness, spyMessageWitness: MerkleMapWitness;

    spy = initializeSpy();
    spyNullifierWitness = nullifierMap.getWitness(spy.spyDigest);
    spyMessageWitness = messageMap.getWitness(spy.spyDigest);

    expect(async () => {
      txn = await Mina.transaction(senderAccount, () => {
       zkAppInstance.updateMessages(
        spyNullifierWitness, 
        spyMessageWitness, 
        VALID_FLAG_MESSAGE
      );
     });
    }).rejects.toThrow(Constants.SPY_CANNOT_SET_MESSAGE_ERROR);
  });

  it ('only whitelisted spies can add messages', async () => {
    let spyOneDigest, spyNullifierWitness: MerkleMapWitness, spyMessageWitness: MerkleMapWitness;

    spyOneDigest = Poseidon.hash(spyOneKey.toPublicKey().toFields());
    spyNullifierWitness = nullifierMap.getWitness(spyOneDigest);

    spyMessageWitness = messageMap.getWitness(spyOneDigest);
    messageMap.set(spyOneDigest, VALID_FLAG_MESSAGE);

    // ----- Adding Spy One to whitelist ----
    txn = await Mina.transaction(senderAccount, () => {
      zkAppInstance.addEligibleAddress(spyNullifierWitness);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    // one spy added in whitelist   
    let numAddresses = zkAppInstance.numAddresses.get();
    expect(numAddresses).toEqual(Field(1));

    // ----- Adding message to spy in whitelist ----
    txn = await Mina.transaction(spyOneAccount, () => {
      zkAppInstance.updateMessages(
        spyNullifierWitness, 
        spyMessageWitness, 
        VALID_FLAG_MESSAGE
      );
    });
    await txn.prove();
    await txn.sign([spyOneKey]).send();

    // message root state changed correctly after adding new message
    const messageRoot = zkAppInstance.messageRoot.get();
    expect(messageRoot).toEqual(messageMap.getRoot());

    // numMessages incremented correctly
    let numMessages = zkAppInstance.numMessages.get();
    expect(numMessages).toEqual(Field(1));
  });

    /* 
      If flag 1 is true, then all other flags must be false  
      If flag 2 is true, then flag 3 must also be true. 
      If flag 4 is true, then flags 5 and 6 must be false.
    */

  it ('can validate flags in a message with validateMessage() function', async () => {

    const message1 = Field(449); // 1110_00001 - condition 1 will be true 
    const message2 = Field(1478); // 10111_000110 - condition 2 will be true
    const message3 = Field(840); // 1101_001000 - condition 3 will be true  
    
    // flags 1, 2, 4 are false, so none of the conditions are triggered. true by default 
    const message4 = Field(36); // 100100
    const message5 = Field(1776); // 11011_110000
    const message6 = Field(0); // 0_00000000
    const message7 = Field(1780); // 11011_110100
    const message8 = Field(740); // 1011_100100

    // invalid flags
    const message9 = Field(1539); // 11000_000011 - condition 1 and 2 will be false 
    const message10 = Field(1475); // 10111000011 - condition 1 and 2 will be false
    const message11 = Field(197); // 11_000101- condition 1 will be false
    const message12 = Field(184); // 10_111000 - condition 3 will be false
    const message13 = Field(138); // 10_001010 - condition 2 will be false
    const message14 = Field(168); // 10_101010 - condition 2 and 3  will be false


    // message1 should be valid
    const message1Valid = zkAppInstance.validateMessage(message1);
    expect(message1Valid).toEqual(Bool(true));

    // message2 should be valid
    const message2Valid = zkAppInstance.validateMessage(message2);
    expect(message2Valid).toEqual(Bool(true));

    // message3 should be valid
    const message3Valid = zkAppInstance.validateMessage(message3);
    expect(message3Valid).toEqual(Bool(true));

    // message4 should be valid
    const message4Valid = zkAppInstance.validateMessage(message4);
    expect(message4Valid).toEqual(Bool(true));

    // message5 should be valid
    const message5Valid = zkAppInstance.validateMessage(message5);
    expect(message5Valid).toEqual(Bool(true));

     // message6 should be valid
    const message6Valid = zkAppInstance.validateMessage(message6);
    expect(message6Valid).toEqual(Bool(true));

    // message7 should be valid
    const message7Valid = zkAppInstance.validateMessage(message7);
    expect(message7Valid).toEqual(Bool(true));

    const message8Valid = zkAppInstance.validateMessage(message8);
    expect(message8Valid).toEqual(Bool(true));

    //message9 should be invalid
    const message9Valid = zkAppInstance.validateMessage(message9);
    expect(message9Valid).toEqual(Bool(false));

    // message10 should be invalid
    const message10Valid = zkAppInstance.validateMessage(message10);
    expect(message10Valid).toEqual(Bool(false));

    // message11 should be invalid
    const message11Valid = zkAppInstance.validateMessage(message11);
    expect(message11Valid).toEqual(Bool(false));

    // message12 should be invalid
    const message12Valid = zkAppInstance.validateMessage(message12);
    expect(message12Valid).toEqual(Bool(false));

    // message13 should be invalid
    const message13Valid = zkAppInstance.validateMessage(message13);
    expect(message13Valid).toEqual(Bool(false));

    // message14 should be invalid
    const message14Valid = zkAppInstance.validateMessage(message14);
    expect(message14Valid).toEqual(Bool(false));
  });

  it ('cannot add a message with invalid flags', async () => {
    let spyOneDigest, spyNullifierWitness: MerkleMapWitness, spyMessageWitness: MerkleMapWitness;

    spyOneDigest = Poseidon.hash(spyOneKey.toPublicKey().toFields());
    spyNullifierWitness = nullifierMap.getWitness(spyOneDigest);

    spyMessageWitness = messageMap.getWitness(spyOneDigest);
    messageMap.set(spyOneDigest, VALID_FLAG_MESSAGE);

    // ----- Adding Spy One to whitelist ----
    txn = await Mina.transaction(senderAccount, () => {
      zkAppInstance.addEligibleAddress(spyNullifierWitness);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    // one spy added in whitelist   
    let numAddresses = zkAppInstance.numAddresses.get();
    expect(numAddresses).toEqual(Field(1));

    // ----- Adding message to spy in whitelist ----
    expect(async () => {
      txn = await Mina.transaction(spyOneAccount, () => {
       zkAppInstance.updateMessages(
        spyNullifierWitness, 
        spyMessageWitness, 
        INVALID_FLAG_MESSAGE
      );
     });
    }).rejects.toThrow(Constants.INVALID_MESSAGE_FLAGS_ERROR);

  });

  it('only admin can add accounts to whitelist', async () => {
    let spy, spyKey, spyWitness: MerkleMapWitness;

    spy = initializeSpy();
    spyWitness = nullifierMap.getWitness(spy.spyDigest);
    
    expect(async () => {
      txn = await Mina.transaction(notAdminAccount, () => {
       zkAppInstance.addEligibleAddress(spyWitness);
     });
   }).rejects.toThrow(Constants.NOT_ADMIN_ERROR);
  });


});

