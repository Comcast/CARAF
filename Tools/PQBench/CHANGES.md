# PQBench Changes

This file gives an overview of the changes in each version of PQBench.

## PQBench Releases
- [PQBench 1.2 (CARAF 3.2)](CHANGES.md#pqbench-12-caraf-32)
- [PQBench 1.1 (CARAF 3.1)](CHANGES.md#pqbench-11-caraf-31)
- [PQBench 1.0 (CARAF 3.0)](CHANGES.md#pqbench-10-caraf-30)

## PQBench 1.2 (CARAF 3.2)
This release focuses on adding new metrics:
- Memory performance metrics: key size, signature size, and memory consumption.
- Compound metrics: certificate throughput, TLS throughput.
Additionally, we also added more details to the types (i.e., signature and KEM) and list of PQC algorithms.

## PQBench 1.1 (CARAF 3.1)
We add a computational performance metric called shared key derivation time that is necessary in measuring the performance of key exchange algorithms like Diffie-Hellman (e.g., ECDHE) in classical cryptography and ML-KEM in PQC.

## PQBench 1.0 (CARAF 3.0)

This release focuses on PQBench, a performance evaluation tool and guide that offer a curated collection of cryptographic use cases, each mapped to relevant evaluation metrics tailored for Post-Quantum Cryptography (PQC).

It provides:
- A categorized list of cryptographic use cases.
- Mappings between use cases and appropriate evaluation metrics.
- Practical guidance on selecting metrics based on deployment context.
- Step-by-step instructions for measuring system performance post-migration.