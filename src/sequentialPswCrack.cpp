#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <crypt.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

static const char ALPHABET[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
static const int ALPHABET_LEN = 64;
static const int PASSWORD_LEN = 8;
static const char* PREFIX = "Fir3nz"; // 6 noti, suffisso 2 (demo velcoe: 4096)
static const int PREFIX_LEN = 6;
static const int SUFFIX_LEN = PASSWORD_LEN - PREFIX_LEN;
static const char SALT[] = "aB";

static void make_candidate(uint64_t idx, char* out) {
    for (int i = PASSWORD_LEN - 1; i >= 0; --i) {
        if (i >= PREFIX_LEN) {
            out[i] = ALPHABET[idx % ALPHABET_LEN];
            idx /= ALPHABET_LEN;
        } else {
            out[i] = PREFIX[i];
        }
        out[PASSWORD_LEN] = '\0';
    }
}

int main() {
    uint64_t space = 1;
    for (int i = 0; i < SUFFIX_LEN; ++i)
        space *= ALPHABET_LEN;

    // preparo i "target": 3 hash di cui vogliamo trovare la password
    struct crypt_data cd;
    std::memset(&cd, 0, sizeof cd);
    const char* hidden[3] = {"Fir3nzXY", "Fir3nz42", "Fir3nz.z"};
    char target_hash[3][14];
    
    printf("Target da crackare (conosciamo solamente l'hash):\n");
    for(int t = 0; t < 3; ++t) {
        strcpy(target_hash[t], crypt_r(hidden[t], SALT, &cd));
        printf(" target[%d] hash = %s\n", t, target_hash[t]);
    }

    // -- ricerca: proviamo OGNI candidato, confrontiamo l'hash
    char cand[PASSWORD_LEN + 1];
    int found = 0;
    printf("\nScansione di %llu candidati...\n", (unsigned long long)space);
    for(uint64_t i = 0; i < space; ++i) {
        make_candidate(i, cand);
        const char* h = crypt_r(cand, SALT, &cd);
        for (int t = 0; t < 3; ++t) {
            if (strcmp(h, target_hash[t]) == 0) {
                printf(" TROVATA! target[%d] -> '%s' (idx=%llu)\n",
                    t, cand, (unsigned long long)i);
                found++;
            }
        }
    }
    printf("\nTrovate %d/3 password.\n", found);
    return 0;
}