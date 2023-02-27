#ifndef SYST_CENTRAL_H
#define SYST_CENTRAL_H

#include "vote.h"

typedef struct cellKey {
    Key *data;
    struct cellKey *next;
} CellKey;

typedef struct cellProtected {
    Protected *data;
    struct cellProtected *next;
} CellProtected;

typedef struct hashcell {
    Key *key;
    int val;
} HashCell;

typedef struct hashtable {
    HashCell **tab;
    int size;
} HashTable;

void generate_random_data(int nv, int nc);
CellKey *create_cell_key(Key *key);
void ajoute_key_deb(CellKey **LCK, Key *key);
CellKey *read_public_keys(char *nom_fichier);
void print_list_keys(CellKey *LCK);
void delete_cell_key(CellKey *c);
void delete_list_keys(CellKey *LCK);
CellProtected *create_cell_protected(Protected *pr);
void ajoute_protected_deb(CellProtected **LCP, Protected *pr);
CellProtected *read_protected(char *nom_fichier);
void print_list_protecteds(CellProtected *LCP);
void delete_cell_protected(CellProtected *c);
void delete_list_protected(CellProtected *LCP);
void supp_fraude(CellProtected **LCP);
HashCell *create_hashcell(Key *key);
int hash_function(Key *key, int size);
int find_position(HashTable *t, Key *key);
HashTable *create_hashtable(CellKey *keys, int size);
void delete_hashtable(HashTable *t);
Key *compute_winner(CellProtected *decl, CellKey *candidates, CellKey *voters, int sizeC, int sizeV);

#endif