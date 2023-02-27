#ifndef PRIME_H
#define PRIME_H

int is_prime_naive(long p);
long modpow_naive(long a, long m, long n);
long modpow(long a, long m, long n);
int witness(long a, long b, long d, long p);
int is_prime_millier(long p, int k);
long random_prime_number(int low_size, int up_size, int k);
//long random_prime_number_dec(int low_size, int up_size, int k, long *decalage);

#endif