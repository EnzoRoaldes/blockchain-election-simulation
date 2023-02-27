#ifndef BLOCK_H
#define BLOCK_H

#include "block.h"
#include "vote.h"
#include "syst_central.h"

typedef struct block {
    Key *author;
    CellProtected *votes;
    unsigned char *hash;
    unsigned char *previous_hash;
    int nonce;
} Block;

typedef struct block_tree_cell {
    Block *block;
    struct block_tree_cell *father;
    struct block_tree_cell *first_child;
    struct block_tree_cell *next_bro;
    int height;
} CellTree;

Block *creer_block(Key *author, CellProtected *votes, unsigned char *hash,
                unsigned char *previous_hash, int nonce);
void ecrire_block(Block *b, char *nom_fichier);
Block *lire_block(char *nom_fichier);
char *block_to_str(Block *b);
unsigned char *str_to_hash(char *s);
void compute_proof_of_work(Block *b, int d);
int verify_block(Block *b, int d);
CellTree *create_node(Block *b);
int update_height(CellTree *father, CellTree *child);
void add_child(CellTree *father, CellTree *child);
void print_tree(CellTree *tree);
void delete_block(Block *b, int delete_votes);
void delete_node(CellTree *node, int delete_votes);
void delete_tree(CellTree *tree, int delete_votes);
CellTree *highest_child(CellTree *cell);
CellTree *last_node(CellTree *cell);
CellProtected *fusion_protected(CellProtected *p1, CellProtected *p2);
CellProtected *get_votes_longest_chain(CellTree *cell);
void submit_vote(Protected *p);
void create_valid_block(CellTree **tree, Key *author, int d);
void add_block(int d, char *name);
CellTree *read_tree();
Key *compute_winner_BT(CellTree *tree, CellKey *candidates, CellKey *voters, int sizeC, int sizeV);

#endif