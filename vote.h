#ifndef VOTE_H
#define VOTE_H

typedef struct key {
    long val;
    long n;
} Key;

typedef struct sign {
    long *tab;
    int taille;
} Signature;

typedef struct protected {
    Key *pKey;
    char *msg;
    Signature *sgn;
} Protected;

void init_key(Key* key, long val, long n);
void afficher_key(Key *key);
void init_pair_keys(Key *pKey, Key *sKey, long low_size, long up_size);
char *nb_to_hexa_str(long val);
char *key_to_str(Key *key);
Key *str_to_key(char *str);
Signature *init_signature(long *content, int size);
Signature *sign(char *mess, Key *sKey);
char *signature_to_str(Signature *sgn);
Signature *str_to_signature(char *str);
Protected *init_protected(Key *pKey, char *mess, Signature *sgn);
int verify(Protected *pr);
char *protected_to_str(Protected *pr);
Protected *str_to_protected(char *str);


#endif