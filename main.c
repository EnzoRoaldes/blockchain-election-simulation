#include <time.h>
#include <stdio.h>
#include <limits.h>
#include "crypto.h"
#include "prime.h"
#include "vote.h"
#include "utilities.h"

void comp_modpow() {
    clock_t temps_initial;
    clock_t temps_final;
    double temps_cpu;
    double temps_cpu2;
    int res;
    FILE *f = fopen("modpownaive_tmps.txt", "w");
    FILE *f2 = fopen("modpow_tmps.txt", "w");
    for (int i = 32; i < 1000000000; i*=2) { //temps pour modpow_naive()
        temps_initial = clock();
        res = modpow_naive(10391, i, 201);
        temps_final = clock();
        temps_cpu = ((double) (temps_final - temps_initial)) / CLOCKS_PER_SEC;
        printf("res = %d, naif tmps = %f, puissance = %d\n", res, temps_cpu, i);
        fprintf(f, "%d %f\n", i, temps_cpu);
    }
    long j;
    for (j = 32; j < LONG_MAX/4; j = j*2) { //temps pour modpow()
        temps_initial = clock();
        res = modpow(10391, j, 201);
        temps_final = clock();
        temps_cpu2 = ((double) (temps_final - temps_initial)) / CLOCKS_PER_SEC;
        printf("res = %d, modpow tmps = %f, puissance = %ld\n", res, temps_cpu2, j);
        fprintf(f2, "%ld %f\n", j, temps_cpu2);
    }
    fclose(f);
    fclose(f2);
}

void comp_isprime() {
    clock_t temps_initial;
    clock_t temps_final;
    double temps_cpu;
    double temps_cpu2;
    int res, res2;
    int k = 5000;
    FILE *f = fopen("isprime.txt", "w");
    for (int i = 1000001; i < 10000001; i+=10000) { //temps pour is_prime_naive() et is_prime_miller()
        temps_initial = clock();
        res = is_prime_naive(i);
        temps_final = clock();
        temps_cpu = ((double) (temps_final - temps_initial)) / CLOCKS_PER_SEC;

        temps_initial = clock();
        res2 = is_prime_millier(i, k);
        temps_final = clock();
        temps_cpu2 = ((double) (temps_final - temps_initial)) / CLOCKS_PER_SEC;
        if (res == 1) { //les cas où p n'est pas premier ne nous intéressent pas.
            printf("res = %d, naif tmps = %f, i = %d\n", res, temps_cpu, i);
            printf("res = %d, miller tmps = %f, i = %d\n", res2, temps_cpu2, i);
            fprintf(f, "%d %f %f\n", i, temps_cpu, temps_cpu2);
        }
    }
    
    fclose(f);
}

int main() { // main pour l'exerice 1
    printf("============ DEBUT COMPARAISON MOD_POW ===============\n");
    comp_modpow();
    printf("============ FIN COMPARAISON MOD_POW ===============\n");
    printf("============ DEBUT COMPARAISON IS_PRIME ===============\n");
    comp_isprime();
    printf("============ FIN COMPARAISON IS_PRIME ===============\n");
    return 0;
}

