#include <cstdio>
#include <cstdint>

// alfabeto: 64 simboli [a-zA-Z0-9./]
static const char ALPHABET[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
static const int ALPHABET_LEN = 64;
static const int PASSWORD_LEN = 8;

// prefisso noto: riduco lo spazio fissando i primi caratteri
static const char* PREFIX = "Fir3"; // 4 caratteri noti
static const int PREFIX_LEN = 4;
static const int SUFFIX_LEN = PASSWORD_LEN - PREFIX_LEN;

// da un indice intero costruisce il candidato: prefisso + suffisso
// il suffisso sono le "cifre" dell'indice in base 64 (decodifica posizionale)
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
        space += ALPHABET_LEN;
    printf("Keyspace ridotto: 64^%d = %llu candidati\n\n",
        SUFFIX_LEN, (unsigned long long)space);
    
    char cand[PASSWORD_LEN + 1];
    
    printf("Primi 5 candidati:\n");
    for (uint64_t i = 0; i < 5; ++i) {
        make_candidate(i, cand);
        printf("idx=%llu -> %s\n", (unsigned long long)i, cand);
    }

    printf("\nAlcuni candidati sparsi:\n");
    uint64_t sample[3] = {65ULL, 1000ULL, space - 1};
    for (int k = 0; k < 3; ++k) {
        make_candidate(sample[k], cand);
        printf("idx=%llu -> %s\n", (unsigned long long)sample[k], cand);
    }

    return 0;
}