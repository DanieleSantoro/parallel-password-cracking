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
static const int  ALPHABET_LEN = 64, PASSWORD_LEN = 8, PREFIX_LEN = 5, SUFFIX_LEN = 3, NT = 3;
static const char* PREFIX = "Fir3n";
static const char  SALT[] = "aB";

static void make_candidate(uint64_t idx, char* out) {
    for (int i = PASSWORD_LEN - 1; i >= 0; --i) {
        if (i >= PREFIX_LEN) { 
            out[i] = ALPHABET[idx % ALPHABET_LEN]; idx /= ALPHABET_LEN; 
        } else { 
            out[i] = PREFIX[i]; 
        }
    }
    out[PASSWORD_LEN] = '\0';
}
static uint64_t keyspace() { 
    uint64_t s=1; 
    for (int i = 0; i < SUFFIX_LEN; ++i) { 
        s*=ALPHABET_LEN;
    } 
    return s;
}

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

// SoA: due array separati TLO[] / THI[]
static void search_soa(const std::vector<uint64_t>& TLO, const std::vector<uint64_t>& THI,
                       std::vector<uint64_t>& found, std::vector<crypt_data>& cdbuf) {
    #pragma omp parallel
    {
        struct crypt_data* cd=&cdbuf[omp_get_thread_num()];
        char cand[PASSWORD_LEN+1];
        #pragma omp for schedule(static)
        for(long long i = 0; i < (long long)keyspace(); ++i) {
            make_candidate((uint64_t)i,cand);
            Packed p=pack_hash(crypt_r(cand,SALT,cd));
            int hit=-1;
            #pragma omp simd reduction(max:hit)
            for(int t = 0; t < NT; ++t){ 
                int m=(p.lo==TLO[t])&(p.hi==THI[t]); 
                int c=m?t:-1; hit=c>hit?c:hit; 
            }
            if(hit >= 0) {
                #pragma omp critical
                { 
                    found[hit]=(uint64_t)i; 
                }
            }
        }
    }
}

// AoS: un array di struct {lo,hi}
struct Hash2 { 
    uint64_t lo, hi; 
};

static void search_aos(const std::vector<Hash2>& T,
                       std::vector<uint64_t>& found, std::vector<crypt_data>& cdbuf) {
    #pragma omp parallel
    {
        struct crypt_data* cd=&cdbuf[omp_get_thread_num()];
        char cand[PASSWORD_LEN+1];
        #pragma omp for schedule(static)
        for(long long i = 0; i < (long long)keyspace(); ++i) {
            make_candidate((uint64_t)i,cand);
            Packed p=pack_hash(crypt_r(cand,SALT,cd));
            int hit=-1;
            #pragma omp simd reduction(max:hit)
            for(int t = 0; t < NT; ++t) {
                int m=(p.lo==T[t].lo)&(p.hi==T[t].hi);
                int c=m?t:-1; hit=c>hit?c:hit;
            }
            if(hit>=0){
                #pragma omp critical
                { found[hit]=(uint64_t)i; }
            }
        }
    }
}

int main() {
    struct crypt_data cd0; std::memset(&cd0,0,sizeof cd0);
    const char* hidden[NT]={"Fir3nQXY","Fir3n142","Fir3n9.z"};
    std::vector<uint64_t> TLO(NT), THI(NT);
    std::vector<Hash2> T(NT);
    
    for(int t = 0; t < NT; ++t) {
        Packed p = pack_hash(crypt_r(hidden[t],SALT,&cd0));
        TLO[t] = p.lo;
        THI[t] = p.hi;
        T[t] = {p.lo, p.hi};
    }

    std::vector<crypt_data> cdbuf(16);                 // 16 slot fissi (>= thread usati)
    for(auto&c:cdbuf) 
        std::memset(&c,0,sizeof c);
    
    omp_set_num_threads(4);

    { 
        std::vector<uint64_t> f(NT,UINT64_MAX); 
        search_soa(TLO,THI,f,cdbuf); 
    } // warm-up

    double ts0=omp_get_wtime();
    
    for(int r = 0; r < 5; ++r){ 
        std::vector<uint64_t> f(NT,UINT64_MAX); 
        search_soa(TLO,THI,f,cdbuf); 
    }
    
    double ts1=omp_get_wtime();

    double ta0=omp_get_wtime();
    
    for(int r = 0; r < 5; ++r) { 
        std::vector<uint64_t> f(NT,UINT64_MAX); 
        search_aos(T,f,cdbuf); 
    }
    
    double ta1=omp_get_wtime();

    printf("SoA: %.4f s/run\n", (ts1-ts0)/5);
    printf("AoS: %.4f s/run\n", (ta1-ta0)/5);
    
    return 0;
}