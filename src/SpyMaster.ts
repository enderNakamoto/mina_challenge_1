import {
    Field,
    Bool,
    SmartContract,
    state,
    State,
    method,
    Gadgets,
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
        const areFlagsValid = this.validateMessage(message);
        areFlagsValid.assertTrue(Constants.INVALID_MESSAGE_FLAGS_ERROR);

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

    
    /* 
      If flag 1 is true, then all other flags must be false  
      If flag 2 is true, then flag 3 must also be true. 
      If flag 4 is true, then flags 5 and 6 must be false.
    */
    validateMessage(message: Field): Bool {

      const flag1Mask = Field(1); // 000001
      const flag2Mask = Field(2); // 000010
      const flag3Mask = Field(4); // 000100
      const flag4Mask = Field(8); // 001000
      const flag5Mask = Field(16); // 010000
      const flag6Mask = Field(32); // 100000
       
      const flag1Bit = Gadgets.and(message, flag1Mask, 6);
      const flag2Bit = Gadgets.and(message, flag2Mask, 6);
      const flag3Bit = Gadgets.and(message, flag3Mask, 6);
      const flag4Bit = Gadgets.and(message, flag4Mask, 6);
      const flag5Bit = Gadgets.and(message, flag5Mask, 6);
      const flag6Bit = Gadgets.and(message, flag6Mask, 6);
    
      const flag1: Bool = flag1Bit.equals(flag1Mask);
      const flag2: Bool = flag2Bit.equals(flag2Mask);
      const flag3: Bool = flag3Bit.equals(flag3Mask);
      const flag4: Bool = flag4Bit.equals(flag4Mask);
      const flag5: Bool = flag5Bit.equals(flag5Mask);
      const flag6: Bool = flag6Bit.equals(flag6Mask);

      // only raise error if any of the conditions fail, if flags 1, 2 and 4 are false,
      // then there is no need to check the other bits 

      // condition 1: If flag 1 is true, then all other flags must be false 
      const condition1 = (flag1.not()).or(flag1.and(flag2.or(flag3).or(flag4).or(flag5).or(flag6).not()))

      // condition 2: If flag 2 is true, then flag 3 must also be true.
      const condition2 = (flag2.not()).or(flag2.and(flag3))

      // condition 3: If flag 4 is true, then flags 5 and 6 must be false.
      const condition3 = (flag4.not()).or(flag4.and(flag5.or(flag6).not()))

      const validResult = condition1.and(condition2).and(condition3)

      return validResult
    }
}
