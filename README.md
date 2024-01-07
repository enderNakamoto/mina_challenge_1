# Mina zkApp: Challenge_1

## How to build

```sh
npm run build
```

## How to run tests

```sh
npm run test
npm run testw # watch mode
```

## How to run coverage

```sh
npm run coverage
```

## How it works 

### Problem 1:
100 eligible addresses stored, only eligible addresses, can deposit 
a secret message. 

### Solution 1:
Merkle Tree of eligible addresses, merkle tree of height 8,
number of leaves = 2^(8-1) is 128, Merkle tree wih height 8 is sufficient

Merkle Tree, Nullifier Tree or just Merkle Map ?
Using Merkle Map, 
1. Initiate whitelist of eligible addresses
  a. Merkle Map withh Track Key Value Pair of -> Address(Key) -> Bool(False)
  b. can check if address is eligible by checking if value is false
  c. if false, then address is eligible
  d. if null, then address is not initiated (not in whitelist)
  e.  if true, then address has already deposited a secret message
  f. after Message is deposited, update value to true


--- 

### Problem 2: 
Count the number of messages

### Solution 2:
Simple Counter state variable to store the number of messages

--- 

### Problem 3: 
Store the Message

### Solution 3:
Another Merkle Map with Key Value Pair of -> Address(Key) -> Message(Value)

---

### Problem 4:
Bits in Message with Flags 

### Soultion 4: 



## License

[Apache-2.0](LICENSE)
