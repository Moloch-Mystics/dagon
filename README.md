# Dagon (𒀭)
> minimalist and modular governance abstraction for accounts today through singleton extensions

![MVIV](https://github.com/Moloch-Mystics/dagon/assets/92001561/671fe3dc-92ee-4c38-8004-982100203465)

Built with *[Foundry](https://github.com/foundry-rs/forge-std)* and *[Solady](https://github.com/vectorized/solady)*.

## Premise

Dagon is a contract singleton that allows any account to give any token a threshold right to sign for it. It thus supports existing token communities and DAO deployments right out-of-the-gate. Dagon is optimized especially for most off-chain voting methods, such as multisig and weighted snapshot proposals, as well, initially offers a platform-agnostic upgrade path into smart account-based governance abstraction.

Chiefly, by just validating contract signature process and not dealing with execution or more opinionated proposal logic, Dagon can complement more organizations today, as well as serve as a source of record for the greater DAO ecosystem, which are all free to implement their own custom hooks and checks to Dagon validation. In V0, which is focused as a voting engine, the Dagon pattern can be used for offchain polling for any token, including `ERC-20`, `ERC-721`, `ERC-1155`, `ERC-6909`, and includes a native token mint and burn function to allow tokens to upgrade (or new tokens to be issued) under `DAGON` (itself `ERC-6909`), but can also validate onchain user operations (userOps) that submit ownership to Dagon validation using the `ERC-173` `transferOwnership` flow.

For example, DAOs might use Dagon singletons in small ways to start as an extension to their ordinary operating system and governor contracts, such as to prove the results of group polls and for simple dapp display purposes, but if Dagon is also registered as the owner of a group smart account (which could be earmarked or the full treasury), Dagon can then work as the DAO's proposal engine, validating userOps and letting them be posted onchain. In this mode, Dagon supports both token-weighted and m/n signature schemes. Collection of Dagon signatures is gasless, and can be posted in a single transaction through the Dagon `isValidSignature` function in response to a typical `ERC-4337` userOp flow.

Overall, Dagon is designed with `ERC-4337`-enabled contracts and account abstraction in mind, but works well enough for accounts that at least support both the `ERC-1271` (Contract Signatures) and `ERC-173` (Ownership) standard interfaces. (Even so, a raw EOA can nonetheless mint a Dagon personal token and authorize a threshold to sign-off for their off-chain or legal purposes.) There is likely much to explore.

## Getting Started

Run: `curl -L https://foundry.paradigm.xyz | bash && source ~/.bashrc && foundryup`

Build the foundry project with `forge build`. Run contract tests with `forge test`. Measure gas fees with `forge snapshot`. Format code with `forge fmt`.

## Disclaimer

*These smart contracts and testing suite are being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of anything provided herein or through related user interfaces. This repository and related code have not been audited and as such there can be no assurance anything will work as intended, and users may experience delays, failures, errors, omissions, loss of transmitted information or loss of funds. The creators are not liable for any of the foregoing. Users should proceed with caution and use at their own risk.*

## License

See [LICENSE](./LICENSE) for more details.
