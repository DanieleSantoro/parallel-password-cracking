#ifndef _GNU_SOURCE 
#define _GNU_SOURCE
#endif
#include <crypt.h>
#include <cstdio>
#include <cstring>

int main() {
    // buffer di lavoro di crypt_r. 
    // Lo azzero prima di usarlo.

    struct crypt_data cd;
    std::memset(&cd, 0, sizeof cd);

    const char* password = "Fir3nz3"; // la voglio nascondere
    const char* salt = "aB"; // salt DES noto

    // crypt_r: hash DES della password, usando il salt. 
    // Thread-safe.
    char* hash = crypt_r(password, salt, &cd);

    printf("password: %s\n", password);
    printf("salt: %s\n", salt);
    printf("hash: %s (lunghezza %zu)\n", hash, strlen(hash));
    return 0;
}