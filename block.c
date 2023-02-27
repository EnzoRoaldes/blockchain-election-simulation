/*
Fonctions pour gérer les blocks et les arbres de blocks
*/

#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <assert.h>
#include "block.h"
#include "vote.h"
#include "syst_central.h"
#include "utilities.h"

/*
Fonction : nous permet d'allouer et d'initialiser un block
*/
Block *creer_block(Key *author, CellProtected *votes, unsigned char *hash,
                unsigned char *previous_hash, int nonce) {
    Block *b = (Block *) malloc(sizeof(Block));
    if (!verif(b != NULL, 0)) return NULL;
    b->author = author;
    b->votes = votes;
    // gestion du cas hash = NULL car on dans quelques cas on passe NULL en appelant cette fonction.
    if (hash != NULL) {
        b->hash = strdup(hash);
    } else {
        b->hash = NULL;
    }
    b->previous_hash = strdup(previous_hash);
    b->nonce = nonce;
    return b;
}

/*
Fonction : écrire un bloc dans un fichier
Commentaire : le format d'écriture d'un block dans un fichier est :
author hash previous_hash nonce
vote1
vote2
...
voteN
*/
void ecrire_block(Block *b, char *nom_fichier) {
    if (!verif(b != NULL && nom_fichier != NULL, 1)) return;
    FILE *f = fopen(nom_fichier, "w");
    if (!verif(f != NULL, 3)) return;
    char *key_str = key_to_str(b->author);
    fprintf(f, "%s %s %s %d\n", key_str,
        b->hash, b->previous_hash, b->nonce);
    free(key_str);

    CellProtected *tmp = b->votes;
    while (tmp != NULL) {
        char *protected_str = protected_to_str(tmp->data);
        fprintf(f, "%s\n", protected_str);
        free(protected_str);
        tmp = tmp->next;
    }
    fclose(f);
}

/*
Fonction : lire un bloc depuis un fichier
Commentaire : on lit selon le format donné dans la fonction d'écriture.
*/
Block *lire_block(char *nom_fichier) {
    if (!verif(nom_fichier != NULL, 1)) return NULL;
    FILE *f = fopen(nom_fichier, "r");
    if (!verif(f != NULL, 3)) return NULL;
    char *str_author = (char *) malloc(sizeof(char)*64);
    CellProtected *votes = NULL;
    unsigned char *hash = (char *) malloc(sizeof(char)*256);
    unsigned char *previous_hash = (char *) malloc(sizeof(char)*256);
    if (!verif(str_author != NULL && hash != NULL && previous_hash != NULL, 0)) return NULL;
    int nonce;
    char l1[512];
    char str_protected[4096];
    // lecture de la première ligne l1 de la forme : author hash previous_hash nonce
    fgets(l1, sizeof(char)*4096, f);
    // stockage des valeurs de la ligne lue dans les variables respectives.
    if (sscanf(l1, "%s %s %s %d\n", str_author, hash, previous_hash, &nonce) == 4) {
        // lecture des N votes, ligne par ligne.
        while(fgets(str_protected, sizeof(char)*4096, f) != NULL) {
            ajoute_protected_deb(&votes, str_to_protected(str_protected));
        }
        // création du block lu.
        Block *b = creer_block(str_to_key(str_author), votes, hash, previous_hash, nonce);
        free(str_author);
        free(hash);
        free(previous_hash);
        return b;
    }
    free(str_author);
    free(hash);
    free(previous_hash);
    printf("Erreur format du fichier\n");
    return NULL;
}

/*
Fonction : traduire un bloc en chaine de caractères
Commentaire : le format de la chaîne est le même format d'écriture d'un block dans un fichier,
on fait donc les mêmes opérations que dans la fonction ecrire_block()
*/
char *block_to_str(Block *b) {
    if (!verif(b != NULL, 1)) return NULL;
    char *res = (char *) malloc(sizeof(char)*4608);
    if (!verif(res != NULL, 0)) return NULL;
    res[0] = '\0';
    char *str_key = key_to_str(b->author);
    if (!verif(strcat(res, str_key) != NULL, 3)) return NULL;
    if (!verif(strcat(res, " \0") != NULL, 3)) return NULL;
    if (!verif(strcat(res, "\n\0") != NULL, 3)) return NULL;
    CellProtected *tmp = b->votes;
    char *str_protec;
    while (tmp != NULL) {
        str_protec = protected_to_str(tmp->data);
        if (!verif(strcat(res, str_protec) != NULL, 3)) return NULL;
        if (!verif(strcat(res, "\n\0") != NULL, 3)) return NULL;
        tmp = tmp->next;
        free(str_protec);
    }
    
    char str_nonce[16];
    sprintf(str_nonce, "%d", b->nonce);
    if (!verif(strcat(res, str_nonce) != NULL, 3)) return NULL;
    free(str_key);
    return res;
}


/*
Fonction : hachage d'une chaîne de caractère grâce à la fonction SHA256
*/
unsigned char *str_to_hash(char *s) {
    if (!verif(s != NULL, 1)) return NULL;
    unsigned char *res = (unsigned char *) malloc(sizeof(char)*256);
    if (!verif(res != NULL, 0)) return NULL;
    unsigned char *d = SHA256(s, strlen(s), 0);
    // on convertit caractère par caractère la chaîne retournée par SHA256() en héxadécimal.
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&res[i], "%02x" , d[i]);
    }
    return res;
}


/*
Fonction : permet de trouver le nonce d'un block 
Remarques : on utilise la brut force en augmentant nonce un à un
jusqu'à ce que le résultat commence bien par d 0 successifs.
*/
void compute_proof_of_work(Block *b, int d) {
    if (!verif(b != NULL, 1)) return;
    b->nonce = 0;
    int i;
    unsigned char *res;
    char *tmp;
    while (1) {
        tmp = block_to_str(b);
        res = str_to_hash(tmp);
        for (i = 0; i < d; i++) {
            if (res[i] != '0') break;
        }
        free(tmp);
        free(res);
        if (i == d) {
            return;
        }
        (b->nonce)++;
    }
}


/*
Fonction : vérifier si le nonce d'un block est valide
i.e : vérifier que le hash du bloc commence bien par d 0 successifs
*/
int verify_block(Block *b, int d) {
    if (!verif(b != NULL, 1)) return 0;
    for (int i = 0; i < d; i++) {
        if (b->hash[i] != '0') {
            return 0;
        }
    }
    return 1;
}


/*
Fonction :  créer et initialiser un noeud
*/
CellTree *create_node(Block *b) {
    CellTree *node = (CellTree *) malloc(sizeof(CellTree));
    if(!verif(node != NULL, 0)) return NULL;
    node->block = b;
    node->father = NULL;
    node->first_child = NULL;
    node->next_bro = NULL;
    node->height = 0;
    return node;
}


/*
Fonction : mettre à jour la hauteur du noeud father quand l’un de ses fils a été modifié
*/
int update_height(CellTree *father, CellTree *child) {
    if (father == NULL || child == NULL) {
        return 0;
    }
    // si la hauteur du père est plus petite que celle de child + 1, alors
    // on doit modifier la hauteur du père car sa chaîne la plus longue
    // est désormais celle du child.
    if (father->height < child->height + 1) {
        father->height = child->height + 1;
        // comme nous avons modifié le père il faut maintenant faire la même 
        // opération pour son père (father->father)
        update_height(father->father, father);
        return 1;
    }
    return 0;
    
}


/*
Fonction : ajouter un fils à un noeud
Commentaire : on ajoute en tête puis on update_height() pour assurer que
les tous les noeuds ont la bonne taille.
*/
void add_child(CellTree *father, CellTree *child) {
    if (!verif(father != NULL && child != NULL, 1)) return;
    child->father = father;
    CellTree *tmp = father->first_child;
    father->first_child = child;
    child->next_bro = tmp;
    update_height(father, father->first_child);
}


/*
Fonction : afficher un arbre
(pour chaque noeud on affiche : hauteur + hash)
Commentaire : on effectue l'affichage de façon récursive sur tous ses fils car chaque fils est un arbre.
*/
void print_tree(CellTree *tree) {
    if (tree == NULL) return;
    printf("%d %s\n", tree->height, tree->block->hash);
    CellTree *son = tree->first_child;
    while(son != NULL) {
        print_tree(son);
        son = son->next_bro;
    }
}


/*
Fonction : permet de supprimer un block selon le paramètre delete_votes
Commentaire : en utilisant delete_block comme demandé dans l'énnoncé, nous avons
remarqué des fuites mémoires avec valgrind que nous n'avons pas réussi à gérer autrement qu'en
modifiant cette fonction.
Nous l'avons modifié de façon à ce que le paramètre delete_votes nous permettent de gérer deux cas :
- delete_votes = 0 : permet de free la liste chaînée des votes sans free leur contenu,
    utile pour un arbre utilisé dans la fonction compute_winner_BT(). En effet, compute_winner_BT()
    créé la liste de votes à partir de l'arbre tree pour déterminer le gagnant et libère cette liste
    ensuite, donc les contenu de chaque éléments de la liste des votes sera déjà libéré.
    Par exemple, l'arbre res dans la fonction exercice9() de block_main.c
- delete_votes = 1 : permet de free la liste chaînée des votes ainsi que leur contenu.
    utile dans les autres cas (quand on utilise pas l'arbre pour compute_winner_BT())
    Par exemple, l'arbre tree dans exercice9() de block_main.c
De même on free aussi l'autheur car les autheur ne sont pas free dans les blocks à chaque fois.
*/
void delete_block(Block *b, int delete_votes) {
    if (b == NULL) return;
    free(b->hash);
    free(b->previous_hash);
    free(b->author);
    if (delete_votes == 0) {
        CellProtected *tmp = b->votes;
        CellProtected *tmpsuiv;
        while (tmp != NULL) {
            tmpsuiv = tmp->next;
            free(tmp);
            tmp = tmpsuiv;
        }
    } else {
        delete_list_protected(b->votes);
    }
    free(b);
}


/*
Fonction : supprime un noeud de l’arbre
*/
void delete_node(CellTree *node, int delete_votes) {
    if (node == NULL) return;
    delete_block(node->block, delete_votes);
    free(node);
}


/*
Fonction : supprime un arbre
Commentaire : on supprime chaque noeuds par appel récursif sur les fils de chaque noeud.
*/
void delete_tree(CellTree *tree, int delete_votes) {
    if (tree == NULL) return;
    CellTree *son = tree->first_child;
    CellTree *tmp_previous_bro;
    while(son != NULL) {
        tmp_previous_bro = son;
        son = son->next_bro;
        delete_tree(tmp_previous_bro, delete_votes);
    }
    delete_node(tree, delete_votes);
}


/*
Fonction : renvoie le noeud fils avec la plus grande hauteur
Commentaire : on parcourt tous les fils du noeuds cell jusqu'à trouver
le premier fils dont la taille + 1 est égal à la taille de cell qui est bien
le fils le plus grand.
*/
CellTree *highest_child(CellTree *cell) {
    if(!verif(cell != NULL, 1)) return NULL;
    CellTree *son = cell->first_child;
    if (son == NULL) {
        return cell;
    }
    while(son->next_bro != NULL && ((son->height + 1) != cell->height)) {
        son = son->next_bro;
    }

    if (son->height + 1 != cell->height) {
        // on verifie que le fils trouvé est le bon (pour gérer le cas où aucun fils n'a la bonne taille)
        // si on rentre dans ce if cela signifie que l'arbre n'est pas bon.
        printf("Erreur HC\n");
        return NULL;
    }
    return son;
}


/*
Fonction : retourne le dernier noeud de la plus longue chaîne d'un arbre
Commentaire : on appelle de façon récursive sur le fils de plus grande taille de cell jusqu'à
arriver à la feuille.
*/
CellTree *last_node(CellTree *cell) {
    if (!verif(cell != NULL, 1)) return NULL;
    if (cell->first_child == NULL) {
        return cell;
    }
    return last_node(highest_child(cell));
}


/*
Fonction : fusionner deux listes chaînées de déclarations signées
Commentaire : on parcourt p2 et on ajoute à chaque fois le contenu de p2 dans p1.
*/
CellProtected *fusion_protected(CellProtected *p1, CellProtected *p2) {
    while (p2 != NULL) {
        ajoute_protected_deb(&p1, p2->data);
        p2 = p2->next;
    }
    return p1;
}


/*
Fonction : retourner la liste obtenue par fusion des listes chaînées 
de déclarations contenues dans les blocs de la plus longue chaîne
Commentaire : on parcourt la chaîne la plus longue en fusionnant les votes dans une
unique liste chaînée res.
*/
CellProtected *get_votes_longest_chain(CellTree *cell) {
    if (!verif(cell != NULL, 1)) return NULL;
    CellProtected *res = NULL;
    CellTree *h_child = highest_child(cell);
    res = fusion_protected(res, cell->block->votes);
    res = fusion_protected(res, h_child->block->votes);
    while (h_child->first_child != NULL) {
        h_child = highest_child(h_child);
        res = fusion_protected(res, h_child->block->votes);
    }
    return res;
}


/*
Fonction : soumettre un vote
i.e : écriture du vote à la fin du fichier "Pending_votes.txt"
*/
void submit_vote(Protected *p) {
    FILE *f = fopen("./Blockchain/Pending_votes.txt", "a");
    if (!verif(f != NULL, 3)) return;
    char *protected_str = protected_to_str(p);
    fprintf(f, "%s\n", protected_str);
    free(protected_str);
    fclose(f);
}


/*
Fonction : créé un bloc valide contenant les votes en attente dans le fichier "Pending_votes.txt"
Commentaire : vu que cette fonction dépend de l'arbre tree, à chaque fois que nous
créons un block valide nous l'ajoutont directement à l'arbre : en effet, l'énnoncé ne nous
indique pas une façon pour créer l'arbre.
*/
void create_valid_block(CellTree **tree, Key *author, int d) {
    // cas où l'arbre est vide.
    if (*tree == NULL) {
        CellProtected *LCP = read_protected("./Blockchain/Pending_votes.txt");
        Key *volontaire = (Key *) malloc(sizeof(Key));
        if (!verif(volontaire != NULL, 0)) return;
        init_key(volontaire, author->val, author->n);
        // nous avons décidé de mettre la chaîne "VIDE" pour le previous_hash
        // d'un block qui est la racine d'un arbre.
        // création du block valide.
        Block *b = creer_block(volontaire, LCP, NULL, "VIDE", 0);
        compute_proof_of_work(b, d);
        char *str_b = block_to_str(b);
        b->hash = str_to_hash(str_b);
        free(str_b);
        remove("./Blockchain/Pending_votes.txt");
        ecrire_block(b, "./Blockchain/Pending_block");
        // création de l'arbre qui était vide.
        *tree = create_node(b);
        return;
    }
    CellProtected *LCP = read_protected("./Blockchain/Pending_votes.txt");
    Key *volontaire = (Key *) malloc(sizeof(Key));
    if (!verif(volontaire != NULL, 0)) return;
    init_key(volontaire, author->val, author->n);
    // création du block valide
    Block *b = creer_block(volontaire, LCP, NULL, last_node(*tree)->block->hash, 0);
    compute_proof_of_work(b, d);
    char *str_b = block_to_str(b);
    b->hash = str_to_hash(str_b);
    free(str_b);
    remove("./Blockchain/Pending_votes.txt");
    ecrire_block(b, "./Blockchain/Pending_block");
    // ajout du block valide créé dans l'arbre.
    add_child(last_node(*tree), create_node(b));
}


/*
Fonction : vérifie que le bloc représenté par le fichier "Pending_block" est valide
si oui, on créé un fichier appelé name représentant le bloc, puis l’ajoute dans le répertoire "Blockchain"
*/
void add_block(int d, char *name) {
    if (!verif(name != NULL, 1)) return;
    Block *b = lire_block("./Blockchain/Pending_block");
    if (verify_block(b, d) == 1) {
        ecrire_block(b, name);
    }
    delete_block(b, 1);
    remove("./Blockchain/Pending_block");
}


/*
Fonction : 
1) créé un noeud de l’arbre pour chaque bloc contenu dans le répertoire, stockés dans un tableau
2) on créé l'arbre en reliant les noeuds entre eux
3) on retourne la racine de l'arbre
*/
CellTree *read_tree() {
    DIR *rep = opendir("./Blockchain/");
    if (rep != NULL) {
        Block *b;
        int nb_fichier = 0;
        struct dirent *dir;
        // on compte le nombre de fichier "BlockN.txt" dans le répertoire Blockchain
        // afin de connaître le nombre de block dans l'arbre.
        while ((dir = readdir(rep))) {
            if (strcmp(dir->d_name, "Pending_block") != 0 && strcmp(dir->d_name, "Pending_votes.txt") != 0 &&
                    strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0) {
                nb_fichier++;
            }
        }
        // création du tableau qui contiendra tous les noeuds de l'arbre.
        CellTree **T = (CellTree **) malloc(sizeof(CellTree *)*nb_fichier);
        int i = 0;
        char *nom_f = (char *) malloc(sizeof(char)*64);
        closedir(rep);
        rep = opendir("./Blockchain/");
        if (rep != NULL) {
            // on ajoute les noeuds de l'arbre dans le tableau T en lisant chaque fichier "BlockN.txt"
            while ((dir = readdir(rep))) {
                if (strcmp(dir->d_name, "Pending_block") != 0 && strcmp(dir->d_name, "Pending_votes.txt") != 0 &&
                        strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0) {
                    sprintf(nom_f, "./Blockchain/%s", dir->d_name);
                    b = lire_block(nom_f);
                    T[i] = create_node(b);
                    i++;
                }
            }
            closedir(rep);

            // on relie les noeuds entre noeuds.
            // grâce aux champs previous_hash et hash, on connait la relation père/fils entre les bloks.
            for (i = 0; i < nb_fichier; i++) {
                for (int j = 0; j < nb_fichier; j++) {
                    if (strcmp(T[j]->block->previous_hash, T[i]->block->hash) == 0) {
                        add_child(T[i], T[j]);
                    }
                }
            }

            // on détermine la racine de l'arbre pour la retourner.
            for (i = 0; i < nb_fichier; i++) {
                if (T[i]->father == NULL) {
                    CellTree *res = T[i];
                    free(T);
                    free(nom_f);
                    return res;
                }
            }
            printf("Problème pas de racine trouvée\n");
            free(T);
            free(nom_f);
            return NULL;
        }
        free(T);
        free(nom_f);
    }
    printf("Erreur ouverture répertoire Blockchain.\n");
    return NULL;
}


/*
Fonction : détermine le gagnant de l’élection
*/
Key *compute_winner_BT(CellTree *tree, CellKey *candidates, CellKey *voters, int sizeC, int sizeV) {
    if (!verif(tree != NULL && candidates != NULL && voters != NULL && sizeC > 0 && sizeV > 0, 1)) return NULL;
    // on récupère les votes de la chaîne la plus longue.
    CellProtected *votes = get_votes_longest_chain(tree);
    // on supprime les fraudes
    supp_fraude(&votes);
    // on utilise la fonction compute_winner() avec votes pour déterminer le vainqueur.
    Key *vainqueur = compute_winner(votes, candidates, voters, sizeC, sizeV);
    delete_list_protected(votes);
    return vainqueur;
}