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
static const int  ALPHABET_LEN = 64;
static const int  PASSWORD_LEN = 8;
static const char* PREFIX = "Fir3n";    // 5 noti -> suffisso 3 (262144)
static const int   PREFIX_LEN = 5;
static const int   SUFFIX_LEN = PASSWORD_LEN - PREFIX_LEN;
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

int main() {
    uint64_t space = 1;
    for (int i = 0; i < SUFFIX_LEN; ++i) {
        space *= ALPHABET_LEN;
    }
    const int NT = 3;

    struct crypt_data cd0;
    std::memset(&cd0, 0, sizeof cd0);
    const char* hidden[NT] = {"Fir3nQXY", "Fir3n142", "fir3n9.z"};
    std::vector<std::string> target_hash(NT);
    for (int t = 0; t < NT; ++t)
        target_hash[t] = crypt_r(hidden[t], SALT, &cd0);

    std::vector<uint64_t> found(NT, UINT64_MAX);
    int maxth = omp_get_max_threads();
    std::vector<crypt_data> cdbuf(maxth);
    for (auto& c : cdbuf)
        std::memset(&c, 0, sizeof c);
    
    long long match_count = 0;
    double t0 = omp_get_wtime();

    #pragma omp parallel reduction(+:match_count)
    {
        struct crypt_data* cd = &cdbuf[omp_get_thread_num()];
        char cand[PASSWORD_LEN + 1];

        #pragma omp for schedule(static) 
        for (long long i = 0; i < (long long)space; ++i) {
            make_candidate((uint64_t)i, cand);
            const char* h = crypt_r(cand, SALT, cd);
            for (int t = 0; t < NT; ++t) {
                if (strcmp(h, target_hash[t].c_str()) == 0) {
                    #pragma omp critical 
                    {
                        found[t] = (uint64_t)i;
                    }
                    match_count++;
                }
            }
        }
    }

    double t1 = omp_get_wtime();

    char cand[PASSWORD_LEN + 1];
    printf("Thread: %d | match: %lld | tempo: %.3f s\n", omp_get_max_threads(), match_count, t1 - t0);
    for (int t = 0; t < NT; ++t) {
        make_candidate(found[t], cand);
        printf("  target[%d] -> '%s' (idx=%llu)\n", t, cand, (unsigned long long)found[t]);
    }
    return 0;

}