Here's a checklist for adding a new algorithm to the framework:

**1. Adapter file** — `adapters/crypto_<name>.c`
- [ ] Include `core/inc/crypto_api.h`
- [ ] Implement `keypair`, `sign`, `verify` with correct signatures matching `crypto_ops_t`
- [ ] Define a `const crypto_ops_t <name>_ops` struct with all fields populated

**2. `crypto_api.h`**
- [ ] Add the algorithm to the `crypto_type_t` enum

**3. `benchmark_runner.c`**
- [ ] `extern const crypto_ops_t <name>_ops;`
- [ ] Add `&<name>_ops` to `crypto_registry[]`

**4. `CMakeLists.txt`**
- [ ] Add `adapters/crypto_<name>.c` to `PLATFORM_SOURCES`

**5. `main.c`**
- [ ] Call `execute_signature_benchmark(ALG_<NAME>)` in `main()`

**6. Build & run**
- [ ] `make` from `build/` — zero warnings
- [ ] ELF size check: `arm-none-eabi-size stm32_benchmark.elf` — fits in 1024K flash
- [ ] Renode output shows the new algorithm's keygen/sign/verify cycle counts