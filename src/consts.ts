import {
    Field,
  } from 'o1js';


export namespace Constants {

  // The number of addresses that can be added to the whitelist
  export const MAX_NUM_ADDRESSES = Field(100);

  // NullifierMerkleMap to store address message state (uninitiated, whitelisted, or message set)
  // The key is the address, the value is the message state 
  // if value is Field(0), the address is not in the whitelist
  // if value is Field(1), the address is in the whitelist, but message is not set
  // if value is Field(2), the address is in the whitelist, and message is set
  export const UNINITIALIZED_VALUE = Field(0);
  export const WHITELISTED_VALUE = Field(1);
  export const MESSAGE_SET_VALUE = Field(2);

  export const ALREADY_WHITELISTED_ERROR = 'address already in whitelist';
  export const NOT_WHITELISTED_ERROR = 'address not in whitelist';
  export const MESSAGE_ALREADY_SET_ERROR = 'message already set';
  export const SPY_CANNOT_SET_MESSAGE_ERROR = 'spy is not whitelist or message already set';
}