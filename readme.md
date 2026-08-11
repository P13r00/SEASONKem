# Overview
Benchmarking suite born for the development of the Hybrid Key Encapsulation Mechanisms SEASON, based on the construction presented by Barbosa et al. "X-Wing".
The repository is the practical implementation of the paper _SEASONs: A Hybrid Quantum-Secure Cryptographic Suite for the Internet of Things_, written during an Erasmus+ Internship in the Malmö University in the months June to August 2027, under the supervision of Kayode S. Adewole, with expected publication in Autumn 2026

# SEASON KEMs
The SEASON framework variants are a family of hybrid KEM constructions that explore different design trade-offs around ML-KEM at NIST Level 1, with the exception of SEASON Winter, which follows NIST Level 3.
SEASON 0 serves as the control, pairing ML-KEM-512 with SHA3-256. The remaining variants swap in lightweight-crypto primitives for the combiner to chase specific goals: Spring uses Xoodyak Hash for speed and memory efficiency, Summer uses ASCON-Hash256 for compliance-oriented design, and Autumn uses Esch256 purely for speed.
Winter is the outlier, combining ML-KEM-768 with Esch384 to prioritize both speed and security at a higher security level. Together they sit alongside X-Wing (ML-KEM-768 + SHA3-256 combiner) as comparison points for how KEM primitive and combiner choice affect a hybrid KEM's footprint and performance on constrained hardware.

## Supported Algorithms
The following algorithms were implemented through the libraries X25519-Cortex-M4, WolfSSL, PQM4, LWC finalists (rweather), and included in the benchmark of the study:

- **AEAD**: ChaCha20-Poly1305, AES-GCM-192, AES-GCM-256, Ascon-128, Ascon-80pq, Xoodyak, SPARKLE (128/192/256)
- **KEM / KEX**: ML-KEM-512, ML-KEM-768 (Kyber), X25519
- **Hashing**: SHA3-256, SHAKE256, Ascon-Hash-256, Ascon-XOF, Xoodyak, SPARKLE-Hash (256/384), SPARKLE-XOF (256/384)
- **Hybrid KEM**: X-Wing

# Architecture
 
- **Registry/adapter pattern**: every algorithm is exposed through a fixed ops struct (`crypto_aead_ops_t`, `crypto_kex_ops_t`, etc.), defined in `core/inc/crypto_api.h`.
- **RNG**: centralized through a single hardware-facing source (`platform_rng_init()`, `platform_rng_generate()`, `PQCLEAN_randombytes()`) in `adapters/adapter_rng.c`, following the pqm4 hardware-passthrough pattern. Each platform supplies its own `adapter_rng_seed.c`. wolfCrypt is retained only for the ChaCha20-Poly1305, AES-GCM, and Ed25519 adapters, which use the same RNG plumbing.
- **Build system**: CMake with the `arm-none-eabi-gcc` toolchain; `ALGO_LIST` in `CMakeLists.txt` toggles which adapters are compiled in.
- **Per-algorithm API scoping**: header conflicts between algorithms (e.g. multiple `api.h`s from different PQ candidates) are resolved via per-source-file `COMPILE_FLAGS` rather than global defines.
- **Third-party isolation**: `third_party/` holds vendored dependencies (wolfSSL, pqm4, lwc-finalists, X25519-Cortex-M4) untouched; only files under `adapters/` include their headers directly, which keeps the adapter boundary enforceable.
