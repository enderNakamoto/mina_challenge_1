import {
    Field,
    SmartContract,
    state,
    State,
    method,
    PublicKey,
    Poseidon,
    MerkleMapWitness
  } from 'o1js';

  const MAX_NUM_ADDRESSES = 100;
  const UNINITIALIZED_VALUE = Field(0);
  const WHITELISTED_VALUE = Field(1);
  const MESSAGE_SET_VALUE = Field(2);


  export class SpyMaster extends SmartContract {

    // NullifierMerkleMap to store address message state (uninitiated, whitelisted, or message set)
    // The key is the address, the value is the message state 
    // if value is Field(0), the address is not in the whitelist
    // if value is Field(1), the address is in the whitelist, but message is not set
    // if value is Field(2), the address is in the whitelist, and message is set
    @state(Field) nullifierRoot = State<Field>();


    // MessageMerkleMap to store message for each address
    @state(Field) messageRoot = State<Field>();

    // numMessages to store the number of messages
    @state(Field) numMessages = State<Field>();

    // numAddresses to store the number of eligible addresses
    @state(Field) numAddresses = State<Field>();

    init() {
      super.init();
      this.numMessages.set(Field(0));
      this.numAddresses.set(Field(0));
    }

    // Helper method to load the initial merkle roots
    // Just for testing purposes, not to be used in production
    @method loadExistingData(
      nullInitialRoot: Field, 
      messageInitialRoot: Field,
      numMessages: Field,
      numAddresses: Field,
      ) {
      this.nullifierRoot.set(nullInitialRoot);
      this.messageRoot.set(messageInitialRoot);
      this.numMessages.set(numMessages);
      this.numAddresses.set(numAddresses);
    }

   // add elgible addresses, set value to Field(1), in nullifierMerkeMap
    @method addEligibleAddress(
        addressToAdd: PublicKey,
        keyWitness: MerkleMapWitness,
      ) {
        // STEP 1: change address to key
        const keyToAdd = Poseidon.hash(addressToAdd.toFields());

        // STEP 2: check if the number of addresses reached MAX_NUM_ADDRESSES(100)
        const numAddressesBefore = this.numAddresses.getAndRequireEquals();
        numAddressesBefore.assertLessThan(MAX_NUM_ADDRESSES);

        // STEP 3: check if the address is already in the whitelist
        const nullRootBefore = this.nullifierRoot.getAndRequireEquals();

        const [ derivedNullRoot, key ] = keyWitness.computeRootAndKey(UNINITIALIZED_VALUE);
        derivedNullRoot.assertEquals(nullRootBefore);
        key.assertEquals(keyToAdd);

        // STEP 3: update add address by updating nullifierRoot
        const [ nullRootAfter, _ ] = keyWitness.computeRootAndKey(WHITELISTED_VALUE);
        this.nullifierRoot.set(nullRootAfter);

        // STEP 4: increment numAddresses
        const numAddressesAfter = numAddressesBefore.add(Field(1));
        this.numAddresses.set(numAddressesAfter);
    }

    // add message to elgible addresses, set value to Field(2), in nullifierMerkeMap
    @method updateMessages(
      nullKeyWitness: MerkleMapWitness,
      messageKeyWitness: MerkleMapWitness,
      keyToChange: Field,
      message: Field,
      ) {

        // STEP 1: check whitelist
        const nullRootBefore = this.nullifierRoot.getAndRequireEquals();

        const [ derivedNullRoot, key ] = nullKeyWitness.computeRootAndKey(Field(1));
        derivedNullRoot.assertEquals(nullRootBefore);
        key.assertEquals(keyToChange); 

        // STEP 2: check message flags 

        // STEP 3: update message
        const messageRootBefore = this.messageRoot.getAndRequireEquals();
        const [ derivedMessageRoot, ] = messageKeyWitness.computeRootAndKey(Field(0));
        derivedMessageRoot.assertEquals(messageRootBefore);

        const [ messageRootAfter,  ] = messageKeyWitness.computeRootAndKey(message);
        this.messageRoot.set(messageRootAfter);

        // STEP 4: update nullifierRoot
        const [ nullRootAfter,  ] = nullKeyWitness.computeRootAndKey(Field(2));
        this.nullifierRoot.set(nullRootAfter);

        // STEP 5: increment numMessages
        const numMessagesBefore = this.numMessages.getAndRequireEquals()
        const numMessagesAfter = numMessagesBefore.add(Field(1));
        this.numMessages.set(numMessagesAfter);
    }
}
