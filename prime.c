#include <stdio.h>
#include <stdlib.h>
#include "prime.h"
#include "utilities.h"

/*
Fonction : determiner si un entier p est premier en parcourant tous les diviseurs possibles
*/
int is_prime_naive(long p) {
    if (p < 2) {
        printf("Il faut un nombre p >= 2\n");
        return 0;
    }
    if (p == 2) {
        return 1;
    }
    for (int i = 3; i < p; i++) {
        if (p%i == 0) {
            return 0;
        }
    }
    return 1;
}

/*
Fonction : calcul a^m modulo n de façon naïve (en incrémentant la puissance de a 1 par 1)
*/
long modpow_naive(long a, long m, long n) {
    long res = 1;
    for(long i = 0; i < m; i++) {
        res = (res*a)%n;
    }
    return (res + n) % n; // + n pour gérer le cas a < 0
}

/*
Fonction : calcul a^m modulo n de façon récursive 
Commentaire : on utilise le fait que si a = b mod[n], alors a² = b² mod[n],
ainsi on se ramène toujours dans le cas où la puissance n est paire afin d'utiliser la propriété pour
diviser par 2 à chaque fois et avoir une complexité log2(n).
*/
long modpow(long a, long m, long n) {
    if (m < 0) {
        printf("Il faut m >= 0\n");
        return -1;
    }
    if (m == 0) {
        return 1;
    }
    if (m == 1) {
        return ((a % n) + n) % n; // cas a < 0
    }
    long res;
    if (m % 2 == 0) {
        res = modpow(a, m/2, n);
        return (res*res + n) % n; //on fait + n pour gérer le cas où a < 0
    }
    res = modpow(a, m-1, n);
    return (res*a + n) % n; //pareil pour gérer a < 0
}

//fonction donnée
int witness(long a, long b, long d, long p) {
    long x = modpow(a, d, p);
    if (x == 1) {
        return 0;
    }
    for (long i = 0; i < b; i++) {
        if (x == p-1) {
            return 0;
        }
        x = modpow(x, 2, p);
    }
    return 1;
}

//fonction donnée
long rand_long(long low, long up) {
    return rand() % (up-low + 1) + low;
}

//fonction donnée
int is_prime_millier(long p, int k) {
    if (p == 2) {
        return 1;
    }
    if (!(p & 1) || p <= 1) {
        return 0;
    }

    long b = 0;
    long d = p-1;
    while (!(d & 1)) {
        d = d/2;
        b = b+1;
    }

    long a;
    int i;
    for (i = 0; i < k; i++) {
        a = rand_long(2, p-1);
        if (witness(a, b, d, p)) {
            return 0;
        }
    }
    return 1;
}


//fonction donnée
long random_prime_number(int low_size, int up_size, int k) {
    long deb = 1;
    long fin = 1;
    long i;
    for (i = 0; i < low_size; i++) {
        deb = deb*2;
        fin = fin*2;
    }
    for (int j = i; j <= up_size; j++) {
        fin = fin*2;
    }
    fin = fin-1;
    for (i = deb + 1; i <= fin; i+=2) {
        if (is_prime_millier(i, k) == 1) {
            return i;
        }
    }
    return -1;
}