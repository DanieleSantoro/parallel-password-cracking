# Parallel Password Cracking (OpenMP)

Mid-term project — Parallel Programming, M.Sc. AI @ University of Florence.

Password recovery via exhaustive search over a reduced keyspace, parallelized
with OpenMP. Hashing uses Unix `crypt(3)` DES (deliberately slow). Built up in
incremental stages, from a single hash to the full parallel benchmark.

## Stages (`src/`)

| File | Stage |
|------|-------|
| `pswToHash.cpp`          | Hash one password with `crypt_r` (DES, known salt) |
| `candidatesGen.cpp`      | Generate candidates from the reduced keyspace (prefix + suffix) |
| `sequentialPswCrack.cpp` | Sequential exhaustive search (reference) |
| `parallelPswCrack.cpp`   | OpenMP parallel search (per-thread `crypt_r`, reduction, critical) |
| `validation.cpp`         | Validate parallel output == sequential (checksum) |

## Build

    g++ -O3 -fopenmp -march=native <file>.cpp -lcrypt -o <file>

## Run

    OMP_NUM_THREADS=4 ./validation

## Notes

- `crypt_r` (reentrant) is required: plain `crypt()` is not thread-safe.
- `crypt_r` is a glibc/Linux extension — build on Linux.
