#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <crypt.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <random>
#include <algorithm>
#include <omp.h>

static const int PASSWORD_LEN = 8, NT = 5;
static const char SALT[] = "aB";

struct Packed { 
    uint64_t lo, hi; 
};

static Packed pack_hash(const char* h) {
    Packed p; 
    p.lo=0; 
    p.hi=0; 
    std::memcpy(&p.lo,h,8); 
    std::memcpy(&p.hi,h+8,5); 
    return p;
}

// Carica una wordlist: una password per riga, troncata a 8 caratteri.
static std::vector<std::string> load_wordlist(const char* path) {
    
    std::vector<std::string> words;
    std::ifstream in(path);
    
    if (!in) {
        fprintf(stderr, "ERRORE: non apro '%s'\n", path); 
        exit(1); 
    }
    
    std::string line;
    
    while (std::getline(in, line)) {
        while (!line.empty() && (line.back()=='\n' || line.back()=='\r')) 
            line.pop_back();
        if (line.empty()) 
            continue;
        if ((int)line.size() > PASSWORD_LEN) 
            line.resize(PASSWORD_LEN);
        words.push_back(line);
    }
    return words;
}

// Attacco a dizionario parallelo: ogni thread hasha parole diverse.
static void dict_attack(const std::vector<std::string>& words,
                        const std::vector<uint64_t>& TLO, const std::vector<uint64_t>& THI,
                        std::vector<uint64_t>& found, std::vector<crypt_data>& cdbuf) {
    long long n = (long long)words.size();
    
    #pragma omp parallel
    {
        struct crypt_data* cd = &cdbuf[omp_get_thread_num()];
        
        #pragma omp for schedule(static)
        for (long long i = 0; i < n; ++i) {
            Packed p = pack_hash(crypt_r(words[i].c_str(), SALT, cd));
            int hit = -1;
            
            #pragma omp simd reduction(max:hit)
            for (int t = 0; t < NT; ++t) {
                int m = (p.lo==TLO[t]) & (p.hi==THI[t]);
                int c = m ? t : -1; hit = c>hit ? c : hit;
            }
            
            if (hit >= 0) {
                #pragma omp critical
                { if ((uint64_t)i < found[hit]) 
                    found[hit] = (uint64_t)i; 
                }
            }
        }
    }
}

int main(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] : "wordlist.txt";
    std::vector<std::string> words = load_wordlist(path);
    printf("Wordlist: %zu password caricate da '%s'\n", words.size(), path);

    // NT target DISTINTI: mescolo gli indici e prendo i primi NT.
    struct crypt_data cd0; std::memset(&cd0,0,sizeof cd0);
    std::vector<size_t> idx(words.size());
    for (size_t i=0;i<idx.size();++i) idx[i]=i;
    std::mt19937_64 rng(12345);
    std::shuffle(idx.begin(), idx.end(), rng);

    std::vector<uint64_t> TLO(NT), THI(NT);
    std::vector<std::string> veri(NT);
    for (int t=0;t<NT;++t){
        veri[t] = words[idx[t]];
        Packed p = pack_hash(crypt_r(words[idx[t]].c_str(), SALT, &cd0));
        TLO[t]=p.lo; THI[t]=p.hi;
    }

    std::vector<crypt_data> cdbuf(16);
    for (auto&c:cdbuf) std::memset(&c,0,sizeof c);
    omp_set_num_threads(4);

    std::vector<uint64_t> found(NT, UINT64_MAX);
    double t0 = omp_get_wtime();
    dict_attack(words, TLO, THI, found, cdbuf);
    double t1 = omp_get_wtime();

    printf("\nPassword recuperate (tempo: %.4f s):\n", t1-t0);
    for (int t=0;t<NT;++t){
        bool ok = (found[t] != UINT64_MAX) && (words[found[t]] == veri[t]);
        printf("  target[%d] -> '%s' %s\n", t,
               found[t]!=UINT64_MAX ? words[found[t]].c_str() : "(non trovata)",
               ok ? "OK" : "!!!");
    }
    return 0;
}