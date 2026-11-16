#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif 
#include <crypt.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <omp.h>

static const char ALPHABET[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
static const int  ALPHABET_LEN = 64, PASSWORD_LEN = 8, PREFIX_LEN = 4, SUFFIX_LEN = PASSWORD_LEN - PREFIX_LEN, NT = 3;
static const char* PREFIX = "Fir3n";  // 5 noti -> suffisso
static const char  SALT[] = "aB";

static void make_candidate(uint64_t idx, char* out) {
    for (int i = PASSWORD_LEN - 1; i >= 0; --i) {
        if (i >= PREFIX_LEN) {
            out[i] = ALPHABET[idx % ALPHABET_LEN];
            idx /= ALPHABET_LEN;
        } else {
            out[i] = PREFIX[i];
        }
    }
    out[PASSWORD_LEN] = '\0';
}   

static uint64_t keyspace() { 
    uint64_t s=1;
    for (int i = 0; i < SUFFIX_LEN ; ++i) {
        s*=ALPHABET_LEN;
    } 
    return s;
}

// --- impacchetta un hash DES (13 char) in 2 interi da 64 bit (8 byte) per confronti più veloci ---
struct Packed {
    uint64_t hi, lo;
};

static Packed pack_hash(const char* h) {
    Packed p;
    p.lo = 0;
    p.hi = 0;
    std::memcpy(&p.lo, h, 8); // primi 8 byte
    std::memcpy(&p.hi, h + 8, 5); // ultimi 5 byte (3 di padding a zero)
    return p;
}

// --- target in formato SoA: due array paralleli lo[] e hi[] di interi da 64 bit ---
static void parallel(const std::vector<uint64_t>& target_lo, const std::vector<uint64_t>& target_hi,
                     std::vector<uint64_t>& found, std::vector<crypt_data>& cdbuf) {
    #pragma omp parallel
    {
        struct crypt_data* cd = &cdbuf[omp_get_thread_num()];
        char cand[PASSWORD_LEN + 1];

        #pragma omp for schedule(runtime)
        for (long long i = 0; i < (long long)keyspace(); ++i) {
            make_candidate((uint64_t)i, cand);
            Packed p = pack_hash(crypt_r(cand, SALT, cd));
            int hit = -1;
            // confronto vettorizzabile
            for (int t = 0; t < NT; ++t) {
                int match = (p.lo == target_lo[t]) && (p.hi == target_hi[t]);
                int cand_t = match ? t : -1;
                hit = cand_t > hit ? cand_t : hit;
            }
            if (hit >= 0) {
                #pragma omp critical
                { 
                    found[hit] = (uint64_t)i; 
                }
            }
        }
    }                 
}

int main() {
    struct crypt_data cd0; std::memset(&cd0, 0, sizeof cd0);
    const char* hidden[NT] = {"Fir3nQXY", "Fir3n142", "Fir3n9.z"};
    std::vector<uint64_t> TLO(NT), THI(NT);
    
    for (int t = 0; t < NT; ++t) {
        Packed p = pack_hash(crypt_r(hidden[t], SALT, &cd0));
        TLO[t] = p.lo; THI[t] = p.hi;
    }
    
    std::vector<crypt_data> cdbuf(omp_get_max_threads());
    for (auto& c : cdbuf) std::memset(&c, 0, sizeof c);

    std::vector<uint64_t> found(NT, UINT64_MAX);
    parallel(TLO, THI, found, cdbuf);

    char cand[PASSWORD_LEN + 1];
    for (int t = 0; t < NT; ++t) {
        make_candidate(found[t], cand);
        printf("  target[%d] -> '%s' (idx=%llu)\n", t, cand, (unsigned long long)found[t]);
    }
    return 0;
}