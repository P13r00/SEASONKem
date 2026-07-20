#include "benchmark_runner.h"

void run_signature_benchmarks(void);
void run_aead_benchmarks(void);
void run_kdf_benchmarks(void);
void run_hash_benchmarks(void);
void run_kem_benchmarks(void);
void run_kex_benchmarks(void);

void run_all_benchmarks(void) {
    run_signature_benchmarks();
    run_aead_benchmarks();
    run_hash_benchmarks();
    run_kem_benchmarks();
    run_kex_benchmarks();
}