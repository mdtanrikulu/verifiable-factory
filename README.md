## Verifiable Factory Contract

### Components

#### 1. Verifiable Factory Contract

- The VerifiableFactory contract is responsible for deploying ChildContract instances using CREATE2
- It also handles the verification of deployed contracts:
    - On-chain: Verifies the contract's address and bytecode using CREATE2 and extcodehash.
    - Off-chain: Triggers a CCIP-Read flow when further verification (like storage layout consistency) is required.

#### 2. Child Contract

- The ChildContract is a simple contract deployed by the factory. It stores two key values for MVP purposes:
    - value: A uint256 value passed during deployment.
    - factory: The address of the factory contract that deployed it.
- These storage slots are verified during the off-chain proof process.

#### 3. CCIP Gateway

- This is the off-chain service responsible for providing Merkle proofs of the contract's storage layout. 

### Architecture

```mermaid
sequenceDiagram
    participant User
    participant VerifiableFactory
    participant ChildContract
    participant CCIPGateway

    %% Contract Creation Flow
    User->>VerifiableFactory: Call createContract(_value)
    VerifiableFactory->>VerifiableFactory: generateSalt(address(factory) + msg.sender)
    VerifiableFactory->>VerifiableFactory: getContractBytecode(_value)
    VerifiableFactory->>VerifiableFactory: Use CREATE2 to deploy ChildContract
    VerifiableFactory->>User: Return newContract address
    VerifiableFactory->>ChildContract: Emit ContractCreated(newContract)

    %% Contract Verification Flow
    User->>VerifiableFactory: Call verifyContract(createdContractAddress, _value, user)
    VerifiableFactory->>VerifiableFactory: Check CREATE2 Address
    VerifiableFactory->>ChildContract: Use extcodehash to check runtime bytecode
    alt Bytecode Valid but Storage Verification Needed
        VerifiableFactory->>User: Return OffchainLookup for CCIP-Read
        User->>CCIPGateway: Off-chain request for storage proof
        CCIPGateway->>ChildContract: Query ChildContract storage layout (off-chain)
        CCIPGateway->>User: Return Merkle proof
        User->>VerifiableFactory: Call verifyCallback with proof
        VerifiableFactory->>VerifiableFactory: Verify Merkle proof of storage layout
        VerifiableFactory->>User: Return true/false after proof verification
    else Bytecode or Address Invalid
        VerifiableFactory->>User: Return VerificationFailed
    end
```
