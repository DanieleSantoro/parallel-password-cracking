# Parallel Password Cracking (OpenMP)

Mid-term project — Parallel Programming, M.Sc. Artificial Intelligence @ University of Florence.

Password recovery parallelized with OpenMP, in two attack modes:
**brute-force** over a reduced keyspace, and a **dictionary attack** over the
real RockYou wordlist. Passwords are hashed with Unix `crypt(3)` DES
(deliberately slow — the classic "slowed-down search problem"). The project is
built incrementally, one self-contained stage per file, from a single hash to
the full optimized parallel search.

## Problem

Given a list of `crypt(3)` DES hashes (known salt), recover the plaintext
passwords. The full 8-character keyspace over `[a-zA-Z0-9./]` is `64^8 ≈ 2.8e14`
— infeasible. Two reductions are used:
- **Brute-force**: fix a known prefix, brute-force the unknown suffix (`64^L`).
- **Dictionary**: only test real, common passwords from a wordlist (RockYou).

## Stages (`src/`)

Each file compiles and runs on its own, demonstrating one concept.

| File | Stage | Concept |
|------|-------|---------|
| `pswToHash.cpp`          | 1   | Hash one password with `crypt_r` (DES, known salt) |
| `candidatesGen.cpp`      | 2   | Generate candidates from the reduced keyspace (index → string, base-64) |
| `sequentialPswCrack.cpp` | 3   | Sequential exhaustive search (reference baseline) |
| `parallelPswCrack.cpp`   | 4   | OpenMP parallel search (per-thread `crypt_r`, reduction, critical) |
| `validation.cpp`         | 5   | Validate parallel output == sequential (checksum) |
| `benchmark.cpp`          | 6   | Scaling benchmark: speedup, efficiency, mean/std over threads |
| `vectorizedCrack.cpp`    | 7.1 | Integer-packed hashes + `omp simd` compare, SoA target layout |
| `layoutBenchmark.cpp`    | 7.3 | Memory layout study: SoA vs AoS |
| `dictCrack.cpp`          | 7.4 | Dictionary attack over the real RockYou wordlist |

## Build

    g++ -O3 -fopenmp -march=native <file>.cpp -lcrypt -o <file>

Flags: `-O3` optimization, `-fopenmp` OpenMP, `-march=native` host SIMD,
`-lcrypt` libcrypt. For the no-vectorization variant add `-DNO_SIMD`.

## Run

    OMP_NUM_THREADS=4 ./validation        # correctness check
    ./benchmark                           # scaling table
    OMP_SCHEDULE=static ./benchmark       # pick schedule (static/dynamic,chunk/guided)

### Dictionary attack

Download the real RockYou wordlist (~14M passwords), then run:

    curl -L -o rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
    ./dictCrack rockyou.txt

`rockyou.txt` is large (~133 MB) and is git-ignored — it is not committed.

Tune the brute-force keyspace via `PREFIX` / `PREFIX_LEN` in the source: a
4-character suffix (`64^4`) gives a sequential baseline above 10 s (recommended
for benchmarking); a shorter suffix is faster for quick tests.

## Key design points

- **`crypt_r`, not `crypt`**: plain `crypt()` uses a shared internal buffer and
  is not thread-safe. Each thread gets its own `crypt_data` buffer — the single
  most important correctness requirement.
- **`reduction`** for the match counter: avoids a shared counter and false sharing.
- **`schedule(static)`**: optimal for this uniform workload (no per-chunk
  synchronization overhead, unlike `dynamic`/`guided`).
- **SoA + `omp simd`**: dense target arrays enable a vectorized, branchless compare.
- **One parallel kernel, two attack modes**: brute-force and dictionary share the
  same OpenMP structure — only the candidate source differs.

## Environment

- Linux, GCC/Clang with OpenMP. `crypt_r` is a glibc extension — build on Linux.

## Author

Daniele Santoro — github.com/DanieleSantoro
