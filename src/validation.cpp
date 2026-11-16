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
static const int ALPHABET_LEN = 64;
static const int PASSWORD_LEN = 8;
static const char* PREFIX = "Fir3n";
static const int PREFIX_LEN = 5;
static const int SUFFIX_LEN = PASSWORD_LEN - PREFIX_LEN;
static const char SALT[] = "aB";
static const int NT = 3;

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
    uint64_t s = 1; 
    for (int i = 0; i < SUFFIX_LEN; ++i) 
        s *= ALPHABET_LEN; 
    return s;
}

// --- ricerca SEQUENZIALE (riferimento) ---
static void sequential(const std::vector<std::string>& target, std::vector<uint64_t>& found) {
    struct crypt_data cd;
    std:memset(&cd, 0, sizeof cd);
    char cand[PASSWORD_LEN + 1];
    for (uint64_t i = 0; i < keyspace(); ++i) {
        make_candidate(i, cand);
        const char* h = crypt_r(cand, SALT, &cd);
        for (int t = 0; t < NT; ++t) {
            if (strcmp(h, target[t].c_str()) == 0)
                found[t] = i;
        }
    }
}

// --- ricerca PARALLELA ---
static void parallel(const std::vector<std::string>& target, std::vector<uint64_t>& found,
std::vector<crypt_data>& cdbuf) {
    #pragma omp parallel
    {
        struct crypt_data* cd = &cdbuf[omp_get_thread_num()];
        char cand[PASSWORD_LEN + 1];
        #pragma omp for schedule(static)
        for (long long i = 0; i < (long long)keyspace(); ++i) {
            make_candidate((uint64_t)i, cand);
            const char* h = crypt_r(cand, SALT, cd);
            for (int t = 0; t < NT; ++t)
                if (strcmp(h, target[t].c_str()) == 0) {
                    #pragma omp critical
                    {
                        found[t] = (uint64_t)i;
                    }
                }
        }
    }
}

// --- VALIDAZIONE: i due risultati coincidono? ---
static bool equal_results(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b) {
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

static uint64_t checksum(const std::vector<uint64_t>& v) {
    uint64_t c = 0;
    for (uint64_t x : v)
        c ^= (x + 0x9E3779B97F4A7C15ULL);
    return c;
}

int main() {
    struct crypt_data cd0; std::memset(&cd0, 0, sizeof cd0);
    const char* segreti[NT] = { "Fir3nQXY", "Fir3n142", "Fir3n9.z" };
    std::vector<std::string> target(NT);
    for (int t = 0; t < NT; ++t) target[t] = crypt_r(segreti[t], SALT, &cd0);

    // 1) Calcola il riferimento sequenziale
    std::vector<uint64_t> riferimento(NT, UINT64_MAX);
    sequential(target, riferimento);

    // 2) Calcola il parallelo
    std::vector<crypt_data> cdbuf(omp_get_max_threads());
    for (auto& c : cdbuf) std::memset(&c, 0, sizeof c);
    std::vector<uint64_t> risultato(NT, UINT64_MAX);
    parallel(target, risultato, cdbuf);

    // 3) Confronta
    bool ok = equal_results(riferimento, risultato)
              && (checksum(riferimento) == checksum(risultato));
    printf("Checksum sequenziale: %llu\n", (unsigned long long)checksum(riferimento));
    printf("Checksum parallelo  : %llu\n", (unsigned long long)checksum(risultato));
    printf("\nVALIDAZIONE: %s\n", ok ? "PASS (parallelo == sequenziale)" : "FAIL !!!");
    return 0;
}