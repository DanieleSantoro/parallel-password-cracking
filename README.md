# Parallel Password Cracking (OpenMP)

Mid-term project — Parallel Programming, M.Sc. Artificial Intelligence @ University of Florence.

Password recovery via exhaustive search over a reduced keyspace, parallelized
with OpenMP. Passwords are hashed with Unix `crypt(3)` DES (deliberately slow,
the classic "slowed-down search problem"). The project is built incrementally,
one self-contained stage per file, from a single hash to the full optimized
parallel search.

## Problem

Given a list of `crypt(3)` DES hashes (known salt), recover the plaintext
passwords. The full 8-character keyspace over `[a-zA-Z0-9./]` is `64^8 ≈ 2.8e14`
— infeasible. The search space is reduced by fixing a known prefix and
brute-forcing only the unknown suffix (`64^L` candidates), as required by the
assignment.

## Stages (`src/`)

Each file compiles and runs on its own, demonstrating one concept.

| File | Stage | Concept |
|------|-------|---------|
| `pswToHash.cpp`          | 1 | Hash one password with `crypt_r` (DES, known salt) |
| `candidatesGen.cpp`      | 2 | Generate candidates from the reduced keyspace (index → string, base-64) |
| `sequentialPswCrack.cpp` | 3 | Sequential exhaustive search (reference baseline) |
| `parallelPswCrack.cpp`   | 4 | OpenMP parallel search (per-thread `crypt_r`, reduction, critical) |
| `validation.cpp`         | 5 | Validate parallel output == sequential (checksum) |
| `benchmark.cpp`          | 6 | Scaling benchmark: speedup, efficiency, mean/std over threads |
| `vectorizedCrack.cpp`    | 7 | Integer-packed hashes + `omp simd` compare, SoA target layout |
| `layoutBenchmark.cpp`    | 7 | Memory layout study: SoA vs AoS |

## Build

    g++ -O3 -fopenmp -march=native <file>.cpp -lcrypt -o <file>

Flags: `-O3` optimization, `-fopenmp` OpenMP, `-march=native` host SIMD,
`-lcrypt` libcrypt. For the no-vectorization variant add `-DNO_SIMD`.

## Run

    OMP_NUM_THREADS=4 ./validation        # correctness check
    ./benchmark                           # scaling table
    OMP_SCHEDULE=static ./benchmark       # pick schedule (static/dynamic,chunk/guided)

Tune the keyspace via `PREFIX` / `PREFIX_LEN` in the source: a 4-character
suffix (`64^4`) gives a sequential baseline above 10 s (recommended for
benchmarking); a shorter suffix is faster for quick tests.

## Key design points

- **`crypt_r`, not `crypt`**: plain `crypt()` uses a shared internal buffer and
  is not thread-safe. Each thread gets its own `crypt_data` buffer — the single
  most important correctness requirement.
- **`reduction`** for the match counter: avoids a shared counter and false sharing.
- **`schedule(static)`**: optimal for this uniform workload (no per-chunk
  synchronization overhead, unlike `dynamic`/`guided`).
- **SoA + `omp simd`**: dense target arrays enable a vectorized, branchless compare.

## Environment

- Linux, GCC/Clang with OpenMP. `crypt_r` is a glibc extension — build on Linux.

## Author

Daniele Santoro — github.com/DanieleSantoro
