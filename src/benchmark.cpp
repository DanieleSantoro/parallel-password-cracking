#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <crypt.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
#include <algorithm>
#include <omp.h>

static const char ALPHABET[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
static const int  ALPHABET_LEN = 64, PASSWORD_LEN = 8;
static const char* PREFIX = "Fir3";          // 5 noti -> suffisso 3 (demo); "Fir3" per suffisso 4
static const int   PREFIX_LEN = 4;
static const int   SUFFIX_LEN = PASSWORD_LEN - PREFIX_LEN;
static const char  SALT[] = "aB";
static const int   NT = 3;

// parametri di misura
static const int WARMUP = 1; // run di riscaldamento scartate
static const int MEASURED = 5; // run misurare
static const int THREADS[] = {1, 2, 4, 8, 16};
static const int NCFG = 5;

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

static void parallel(const std::vector<std::string>& target, std::vector<uint64_t>& found,
                     std::vector<crypt_data>& cdbuf){
    #pragma omp parallel
    {
        struct crypt_data* cd = &cdbuf[omp_get_thread_num()];
        char cand[PASSWORD_LEN + 1];

        #pragma omp for schedule(static)
        for (long long i = 0; i < (long long)keyspace(); ++i) {
            make_candidate((uint64_t)i, cand);
            const char* h = crypt_r(cand, SALT, cd);
            for (int t = 0; t < NT; ++t) {
                if (strcmp(h, target[t].c_str()) == 0) {
                    #pragma omp critical
                    { found[t] = (uint64_t)i; }
                }
            }
        }
    }
}

int main() {
    struct crypt_data cd0;
    std::memset(&cd0, 0, sizeof cd0);
    const char* hidden[NT] = {"Fir3nQXY", "Fir3n142", "Fir3n9.z"};
    std::vector<std::string> target(NT);
    for (int t = 0; t < NT; ++t) {
        target[t] = crypt_r(hidden[t], SALT, &cd0);
    }

        int maxth = 16;
        std::vector<crypt_data> cdbuf(maxth);
        for (auto&c : cdbuf) {
            std::memset(&c, 0, sizeof c);
        }

        printf("Keyspace: 64^%d = %llu | target: %d | HW threads: %d\n\n",
                SUFFIX_LEN, (unsigned long long)keyspace(), NT, omp_get_max_threads());
        printf("%-8s %-12s %-10s %-10s %-10s\n","Thread","Media[s]","Dev.std","Speedup","Efficiency");
        printf("------------------------------------------------------------\n");

        double baseline = 0;
        for (int c = 0; c < NCFG; ++c) {
            int nt = THREADS[c];
            omp_set_num_threads(nt);

            // warm-up (scartate)
            for (int w = 0; w < WARMUP; ++w) {
                std::vector<uint64_t> f(NT, UINT64_MAX);
                parallel(target, f, cdbuf);
            }

            // misurate
            std::vector<double> times;
            for (int m = 0; m < MEASURED; ++m) {
                std::vector<uint64_t> f(NT, UINT64_MAX);
                double t0 = omp_get_wtime();
                parallel(target, f, cdbuf);
                double t1 = omp_get_wtime();
                times.push_back(t1 - t0);
            }

            // mean and standard deviation
            double mean = 0;
            for(double x:times) 
                mean += x;
            mean /= times.size();
            
            double acc = 0;
            for (double x:times)
                acc += (x-mean)*(x-mean);
            
            double sd = std::sqrt(acc/(times.size() - 1));

            if (c==0)
                baseline = mean;
            
            double speedup = baseline / mean;
            double eff = speedup / nt * 100.0;
            printf("%-8d %-12.4f %-10.4f %-10.2f %-9.1f%%\n", nt, mean, sd, speedup, eff);
        }
        return 0;
}
