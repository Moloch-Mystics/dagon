# Dagon

Dagon is a contract singleton that allows any account to give any token threshold the right to sign for it.

It is thus proposed as a gas-efficient (and *AA-forward*) abstraction layer to blockchain-based governance. Chiefly, by just validating contract signatures and not dealing with execution or more opinionated proposal logic, Dagon can complement more communities today, as well as serve as a source of record for the greater DAO ecosystem, which are all free to implement their own custom hooks and checks to Dagon validation. In V0, the Dagon pattern can be used for offchain polling for any token, including `ERC-20`, `ERC-721`, `ERC-1155`, `ERC-6909`, and includes a native token mint and burn function, `DAGON`, but can also validate onchain operations that submit ownership to Dagon validation using `ERC-173`.

For example, <Insert> DAOs might use Dagon in small ways to start, such as to validate their membership signatures in the typical snapshot proposal and for simple dapp display purposes, or if Dagon is further registered as the owner of their group smart account, Dagon can work as a proposal engine, validating executions for smart accounts and timelocks. In this mode, Dagon supports both token-weighted and m/n signature schemes. Collection of Dagon signatures is gasless, and can be posted in a single transaction and block fee using `isValidSignature()` in an ERC-4337 userOp flow.

Overall, Dagon is designed with `ERC-4337` and account abstraction in mind to validate group userOps and custody, but works well with accounts that at least support both the `ERC-1271` (Contract Signatures) and `ERC-173` (Ownership) interfaces. Even so, an EOA can nonetheless mint a Dagon personal token and authorize a threshold to return an `isValidSignature()` sign-off for off-chain or legal purposes. There is likely much to explore.


