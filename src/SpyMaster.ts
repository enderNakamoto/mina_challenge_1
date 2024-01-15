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

  import { Constants } from './consts';


  export class SpyMaster extends SmartContract {
    @state(Field) nullifierRoot = State<Field>();
    @state(Field) messageRoot = State<Field>();
    @state(Field) numMessages = State<Field>();
    @state(Field) numAddresses = State<Field>();

    init() {
      super.init();
      this.numMessages.set(Field(0));
      this.numAddresses.set(Field(0));
    }

    // cannot pass in initial state to constructor, so use this method to
    // initialize empty nullifierRoot and messageRoot
    @method initMapRoots(
      nullInitialRoot: Field, 
      messageInitialRoot: Field,
      ) {
      this.nullifierRoot.set(nullInitialRoot);
      this.messageRoot.set(messageInitialRoot);
    }

    // add spies to the whitelist
    @method addEligibleAddress(
        keyWitness: MerkleMapWitness,
      ) {
        let derivedNullRoot, nullRootAfter, _;

        // STEP 1: check if the number of addresses reached MAX_NUM_ADDRESSES(100)
        const numAddressesBefore = this.numAddresses.getAndRequireEquals();
        numAddressesBefore.assertLessThan(Constants.MAX_NUM_ADDRESSES);

        // STEP 2: check if the address is already in the whitelist
        const nullRootBefore = this.nullifierRoot.getAndRequireEquals();
        [ derivedNullRoot, _ ] = keyWitness.computeRootAndKey(Constants.UNINITIALIZED_VALUE);
        derivedNullRoot.assertEquals(nullRootBefore, Constants.ALREADY_WHITELISTED_ERROR);


        // STEP 3: update add address by updating nullifierRoot
         [ nullRootAfter, _ ] = keyWitness.computeRootAndKey(Constants.WHITELISTED_VALUE);
        this.nullifierRoot.set(nullRootAfter);

        // STEP 4: increment numAddresses
        const numAddressesAfter = numAddressesBefore.add(Field(1));
        this.numAddresses.set(numAddressesAfter);
    }

    // add message to the messageRoot, for whielisted spies only  
    @method updateMessages(
      nullKeyWitness: MerkleMapWitness,
      messageKeyWitness: MerkleMapWitness,
      message: Field,
      ) {
        let derivedNullRoot,
        nullRootBefore,
        nullRootAfter,
        derivedMessageRoot,
        messageRootBefore,
        messageRootAfter,
         _ ; // dummy variable for unused return value

        // STEP 1: check whitelist, or message has been set. 
        nullRootBefore = this.nullifierRoot.getAndRequireEquals();
        [ derivedNullRoot, _ ] = nullKeyWitness.computeRootAndKey(Constants.WHITELISTED_VALUE);
        derivedNullRoot.assertEquals(nullRootBefore, Constants.SPY_CANNOT_SET_MESSAGE_ERROR);
  

        // STEP 2: check if message already set (this is redundant, as it is already checked in step 1 from nullifierMap)
        messageRootBefore = this.messageRoot.getAndRequireEquals();
        [ derivedMessageRoot, _ ] = messageKeyWitness.computeRootAndKey(Constants.UNINITIALIZED_VALUE);
        derivedMessageRoot.assertEquals(messageRootBefore, Constants.MESSAGE_ALREADY_SET_ERROR);

        // STEP 3: check message flags 
        

        // STEP 4: update message 
        [ messageRootAfter, _ ] = messageKeyWitness.computeRootAndKey(message);
        this.messageRoot.set(messageRootAfter);
     
        // STEP 5: update nullifierRoot
        [ nullRootAfter, _  ] = nullKeyWitness.computeRootAndKey(Constants.MESSAGE_SET_VALUE);
        this.nullifierRoot.set(nullRootAfter);

        // STEP 5: increment numMessages
        const numMessagesBefore = this.numMessages.getAndRequireEquals()
        const numMessagesAfter = numMessagesBefore.add(Field(1));
        this.numMessages.set(numMessagesAfter);
    }
}
