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

#### 3. EVMGateway

- This is the off-chain service responsible for providing Merkle proofs of the contract's storage layout. 

### Architecture


```mermaid
sequenceDiagram
    participant User
    participant VerifiableFactory
    participant ChildContract
    participant EVMGateway

    %% Contract Creation Flow
    User->>VerifiableFactory: Call createContract(_value)
    VerifiableFactory->>VerifiableFactory: generateSalt(msg.sender)
    VerifiableFactory->>VerifiableFactory: getContractBytecode(_value)
    VerifiableFactory->>VerifiableFactory: Use CREATE2 to deploy ChildContract
    VerifiableFactory->>User: Return newContract address
    VerifiableFactory->>ChildContract: Emit ContractCreated(newContract)

    %% Contract Verification Flow
    User->>VerifiableFactory: Call verifyContract(createdContractAddress)
    VerifiableFactory->>VerifiableFactory: Check CREATE2 Address
    VerifiableFactory->>VerifiableFactory: Use extcodehash to check runtime bytecode
    alt Bytecode and Address Valid
        VerifiableFactory->>VerifiableFactory: Use EVMFetcher to construct fetch request
        VerifiableFactory->>VerifiableFactory: EVMFetcher.fetch(callbackSelector, extraData)
        VerifiableFactory--)User: Reverts with OffchainLookup (handled by fetch())
        User->>EVMGateway: Off-chain HTTP request with fetch payload
        EVMGateway->>ChildContract: Query storage slots (off-chain)
        EVMGateway->>User: Return storage data
        User->>VerifiableFactory: Call verifyCallback(response)
        VerifiableFactory->>VerifiableFactory: Process and verify storage data
        VerifiableFactory->>User: Return verification result (true/false)
    else Bytecode or Address Invalid
        VerifiableFactory->>User: Return VerificationFailed
    end
```
