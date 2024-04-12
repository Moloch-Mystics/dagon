# Dagon (𒀭)
> minimalist and modular governance abstraction for accounts today through singletons

![MVIV](https://github.com/Moloch-Mystics/dagon/assets/92001561/671fe3dc-92ee-4c38-8004-982100203465)

Built with *[Foundry](https://github.com/foundry-rs/forge-std)* and *[Solady](https://github.com/vectorized/solady)*.

## [Beta Deployment](https://contractscan.xyz/contract/0x0000000000001ADDcB933DD5028159dc965b5b7f)
> *Signature Validation Limit: ~1774 signatures*

Chains           | Address                                 | 
----------------|-----------------------------------------|
Ethereum, Arbitrum, Optimism, Base, Blast, Zora, Gnosis, Polygon, Avalanche and BNB (& testnets) | [0x0000000000001ADDcB933DD5028159dc965b5b7f](https://etherscan.io/address/0x0000000000001ADDcB933DD5028159dc965b5b7f#code) |

> Summoner: [0x0000000000008de57636b43B33b2d6007Df5576e](https://etherscan.io/address/0x0000000000008de57636b43B33b2d6007Df5576e#code)

Dagon deployments are generated as [efficient create2 addresses](https://medium.com/coinmonks/on-efficient-ethereum-addresses-3fef0596e263) through the [canonical create2 factory](https://etherscan.io/address/0x0000000000ffe8b47b3e2130213b802212439497#code). As such they share the same exact address and code on every blockchain.

## Premise

Dagon is a contract singleton system that allows any smart contract account to give any token a threshold right to sign for it. This means you can add "more owners" to your smart account. It also means you can give these different owners different "weights" to simulate a DAO voting engine or company captable. Equal weights are equivalent to a multi-sig or coop. These weights can be associated with existing tokens or created within Dagon itself. The sky is the limit as long as [`ERC-173`](https://eips.ethereum.org/EIPS/eip-173) and [`ERC-1271`](https://eips.ethereum.org/EIPS/eip-1271) are followed.

Dagon thus supports existing token communities and DAO deployments out-of-the-gate. This voting format is optimized especially for most off-chain voting methods, like snapshot proposals, as well, initially offers a platform-agnostic upgrade path into smart account-based governance abstraction following, *e.g.*, [`ERC-4337`](https://eips.ethereum.org/EIPS/eip-4337).

## More specifically

By just validating contract signatures remotely for accounts following `ERC-1271`, and not dealing with execution or more opinionated proposal logic, Dagon can complement more organizations today, as well as serve as a source of record for the greater DAO ecosystem, which are all free to implement their own custom hooks and checks to Dagon validation. In `V1`, which is focused as a voting engine, the Dagon pattern can be used for offchain polling for any token, including `ERC-20`, `ERC-721`, `ERC-1155`, `ERC-6909`, and includes a native token mint and burn function to allow tokens to upgrade (or new tokens to be issued) under `DAGON` (itself [`ERC-6909`](https://eips.ethereum.org/EIPS/eip-6909)), but can also validate onchain user operations (`userOp`s) that submit ownership to Dagon validation using the `ERC-173` `transferOwnership` flow.

For example, DAOs might use Dagon singletons in small ways to start as an extension to their ordinary operating system and governor contracts, such as to prove the results of group polls and for simple dapp display purposes, but if Dagon is also registered as the owner of a group smart account (which could be earmarked or the full treasury), Dagon can then work as the DAO's proposal engine, validating userOps and letting them be posted onchain. In this mode, Dagon supports both token-weighted and m/n signature schemes. Collection of Dagon signatures is gasless, and can be posted in a single transaction through the Dagon `isValidSignature` function in response to a typical `ERC-4337` userOp flow.

Overall, Dagon is designed with `ERC-4337`-enabled contracts and account abstraction in mind, but works well enough for accounts that at least support both the `ERC-1271` (Contract Signatures) and `ERC-173` (Ownership) standard interfaces. There is likely much to explore.

## Getting Started

Run: `curl -L https://foundry.paradigm.xyz | bash && source ~/.bashrc && foundryup`

Build the foundry project with `forge build`. Run contract tests with `forge test`. Measure gas fees with `forge snapshot`. Format code with `forge fmt`.

## Disclaimer

*These smart contracts and testing suite are being provided as is. No guarantee, representation or warranty is being made, express or implied, as to the safety or correctness of anything provided herein or through related user interfaces. This repository and related code have not been audited and as such there can be no assurance anything will work as intended, and users may experience delays, failures, errors, omissions, loss of transmitted information or loss of funds. The creators are not liable for any of the foregoing. Users should proceed with caution and use at their own risk.*

## License

See [LICENSE](./LICENSE) for more details.
