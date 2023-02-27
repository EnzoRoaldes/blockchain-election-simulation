/*
Contient les fonctions gérant les listes chaînées de Key et Protected
et gérant les tables de hachage HashTable
*/

#include <stdio.h>
#include <stdlib.h>
#include "syst_central.h"
#include "crypto.h"
#include "prime.h"
#include "vote.h"
#include "utilities.h"

/*
Fonction : Génération dans keys.txt des clés des citoyens, dans candidats.txt des clés des
candidats et dans declarations.txt des votes. Le nombre de votes (et donc de citoyens) est nv
et le nombre de candidats est nc.
*/
void generate_random_data(int nv, int nc) {
    if (!verif(nv > 0 && nc > 0, 1)) return;
    int i;
    FILE *f_keys = fopen("keys.txt", "w");
    if (!verif(f_keys != NULL, 3)) return;
    Key **pKeys = (Key **) malloc(sizeof(Key *)*nv);
    Key **sKeys = (Key **) malloc(sizeof(Key *)*nv);
    if (!verif(pKeys != NULL && sKeys != NULL, 0)) return;
    char *str_pKey;
    char *str_sKey;
    // génération des nv couples de clés (publique, secrète) pour les nv citoyens.
    for (i = 0; i < nv; i++) {
        pKeys[i] = (Key *) malloc(sizeof(Key));
        sKeys[i] = (Key *) malloc(sizeof(Key));
        if (pKeys[i] == NULL || sKeys[i] == NULL) {
            for (int j = 0; j < i; j++) {
                free(pKeys[j]);
                free(sKeys[j]);
            }
            if (pKeys[i] == NULL) {
                free(sKeys[i]);
            } else {
                free(pKeys[i]);
            }
            free(pKeys);
            free(sKeys);
            return;
        }
        init_pair_keys(pKeys[i], sKeys[i], 8, 16);
        str_pKey = key_to_str(pKeys[i]);
        str_sKey = key_to_str(sKeys[i]);
        // écriture des clés dans keys.txt
        fprintf(f_keys, "%s %s\n", str_pKey, str_sKey);
        free(str_pKey);
        free(str_sKey);
    }
    
    FILE *f_candid = fopen("candidates.txt", "w");
    if (!verif(f_candid != NULL, 3)) return;
    Key **candidats = (Key **) malloc(sizeof(Key *)*nc);
    //tableau qui va éviter de rechoisir le même candidat
    int *tab_i = (int *) malloc(sizeof(int)*nv);
    if (!verif(candidats != NULL && tab_i !=  NULL, 0)) return;
    for (int i = 0; i < nv; i++) {
        tab_i[i] = 0;
    }
    int rd;
    char *str_key;
    for (i = 0; i < nc; i++) {
        rd = rand() % nv;
        // sélection nc clés publiques aléatoirement pour définir les nc candidats.
        while (tab_i[rd] == 1) {
            rd = rand() % nv;
        }
        tab_i[rd] = 1;
        candidats[i] = pKeys[rd];
        str_key = key_to_str(pKeys[rd]);
        // écriture des clés choisies dans candidats.txt
        fprintf(f_candid, "%s \n", str_key);
        free(str_key);
    }

    FILE *f_decla_sign = fopen("declarations.txt", "w");
    if (!verif(f_decla_sign != NULL, 3)) return;
    Protected *decla_sign;
    Signature *sgn;
    char *msg;
    char *str_protec;
    // génère une déclaration de vote signée pour chaque citoyen.
    for (i = 0; i < nv; i++) {
        rd = rand() % nc;
        msg = key_to_str(candidats[rd]);
        sgn = sign(msg, sKeys[i]);
        decla_sign = init_protected(pKeys[i], msg, sgn);
        str_protec = protected_to_str(decla_sign);
        // écriture des déclarations dans declarations.txt.
        fprintf(f_decla_sign, "%s\n", str_protec);
        free(msg);
        free(str_protec);
        free(sgn->tab);
        free(sgn);
        free(decla_sign);
    }
    
    fclose(f_keys);
    fclose(f_candid);
    fclose(f_decla_sign);
    for (i = 0; i < nv; i++) {
        free(pKeys[i]);
        free(sKeys[i]);
    }
    free(tab_i);
    free(pKeys);
    free(sKeys);
    free(candidats);
}

/*
Fonction : alloue et initialise une cellule de liste chainée de clés
*/
CellKey *create_cell_key(Key *key) {
    CellKey *LCK = (CellKey *) malloc(sizeof(CellKey));
    if (!verif(LCK != NULL, 0)) return NULL;
    LCK->data = key;
    LCK->next = NULL;
    return LCK;
}

/*
Fonction : ajoute une clé en tête de liste
Commentaire : on créé une cellule avec la clé voulue et on la chaîne avec le reste de la liste,
puis on fait initialise le début de la liste sur ce nouvel élément.
*/
void ajoute_key_deb(CellKey **LCK, Key *key) {
    CellKey *LCK0 = create_cell_key(key);
    if (LCK0 == NULL) return;
    LCK0->next = *LCK;
    *LCK = LCK0;
}

/*
Fonction : prend en entrée le fichier keys.txt ou le fichier candidates.txt, et renvoie la liste chainée
des clés publiques dans le fichier correspondant
et retourne une liste chainée contenant toutes les clés publiques du fichier
Commentaire : lecture du fichier ligne par ligne en ne prenant en compte que la clé publique au début.
*/
CellKey *read_public_keys(char *nom_fichier) {
    if (!verif(nom_fichier != NULL, 1)) return NULL;
    CellKey *LCK = NULL;
    FILE *f = fopen(nom_fichier, "r");
    if (!verif(f != NULL, 3)) return NULL;
    char lu[512];
    char str_key[256];
    while(fgets(lu, sizeof(char)*512, f) != NULL) {
        if (sscanf(lu, "%s ", str_key) != 1) return NULL;
        ajoute_key_deb(&LCK, str_to_key(str_key));
    }
    fclose(f);
    return LCK;
}

/*
Fonction : afficher une liste chainee de cles
Commenaire : on parcourt la liste pour l'afficher
*/
void print_list_keys(CellKey *LCK) {
    while (LCK != NULL) {
        afficher_key(LCK->data);
        LCK = LCK->next;
    }
}

/*
Fonction : on libère la clé dans une cellule
Commentaire : une clé n'ayant aucun champs avec allocation dynamique on free() que la clé en elle même
*/
void delete_cell_key(CellKey *c) {
    if (c == NULL) return;
    free(c->data);
}

/*
Fonction : libère une liste de cellules de clé
Commentaire : on parcourt la liste pour libérer chaque cellule
*/
void delete_list_keys(CellKey *LCK) {
    if (LCK == NULL) return;
    CellKey *tmp = LCK;
    while (tmp != NULL) {
        tmp = LCK->next;
        delete_cell_key(LCK);
        free(LCK);
        LCK = tmp;
    }
    free(LCK);
}

/*
Fonction : alloue et initialise une cellule de liste chainée de Protected
*/
CellProtected *create_cell_protected(Protected *pr) {
    CellProtected *LCP = (CellProtected *) malloc(sizeof(CellProtected));
    if (!verif(LCP != NULL, 0)) return NULL;
    LCP->data = pr;
    LCP->next = NULL;
    return LCP;
}

/*
Fonction : ajoute un Protected en tête de liste si il n'est pas NULL
*/
void ajoute_protected_deb(CellProtected **LCP, Protected *pr) {
    if (pr == NULL) return;
    CellProtected *LCP0 = create_cell_protected(pr);
    LCP0->next = *LCP;
    *LCP = LCP0;
}

/*
Fonction : prend en entree le fichier declarations.txt, et renvoie la liste chainée
des Protected dans le fichier correspondant
Commentaire : on parcourt le fichier ligne par ligne pour créer chaque Protected.
*/
CellProtected *read_protected(char *nom_fichier) {
    if (!verif(nom_fichier != NULL, 1)) return NULL;
    CellProtected *LCP = NULL;
    FILE *f = fopen(nom_fichier, "r");
    if (!verif(f != NULL, 3)) return NULL;
    char str_protected[1024];
    while(fgets(str_protected, sizeof(char)*1024, f) != NULL) {
        ajoute_protected_deb(&LCP, str_to_protected(str_protected));
    }
    fclose(f);
    return LCP;
}

/*
Fonction : affiche une liste chainée de Protected
*/
void print_list_protecteds(CellProtected *LCP) {
    char *str_protec;
    while (LCP != NULL) {
        str_protec = protected_to_str(LCP->data);
        printf("%s\n", str_protec);
        free(str_protec);
        LCP = LCP->next;
    }
}

/*
Fonction : libère une cellule d'une liste chainée de Protected en libérant ses champs alloués
dynamiquement.
*/
void delete_cell_protected(CellProtected *c) {
    if (!verif(c != NULL, 1)) return;
    free(c->data->pKey);
    free(c->data->msg);
    free(c->data->sgn->tab);
    free(c->data->sgn);
    free(c->data);
}

/*
Fonction : libère une liste chainée de Protected en utilisant la fonction précédente.
*/
void delete_list_protected(CellProtected *LCP) {
    if (LCP == NULL) return;
    CellProtected *tmp = LCP;
    while (LCP != NULL) {
        tmp = LCP->next;
        delete_cell_protected(LCP);
        free(LCP);
        LCP = tmp;
    }
    free(LCP);
}

/*
Fonction : Supprime les fraudes dans une liste chainée de Protected grâce à la fonction verify()
Commentaire : On gère d'abord le cas des fraudes en tête de liste, puis on gère le cas des fraudes
qui ne sont pas en tête de liste en raccordant l'élément precédant la fraude à celui qui suit
la fraude.
*/
void supp_fraude(CellProtected **LCP) {
    if (LCP == NULL) return;
    CellProtected *tmp;
    // gestion des cas des fraudes en tête de liste.
    while (*LCP != NULL && !verify((*LCP)->data)) {
        delete_cell_protected(*LCP);
        tmp = (*LCP)->next;
        free(*LCP);
        *LCP = tmp;
    }
    if (*LCP == NULL) return;
    CellProtected *tmpSuiv;
    tmp = *LCP;
    // gestion des fraudes en milieu / fin de liste.
    while (tmp->next != NULL) {
        if (!verify(tmp->next->data)) {
            delete_cell_protected(tmp->next);
            tmpSuiv = tmp->next->next;
            free(tmp->next);
            tmp->next = tmpSuiv;
        }
        tmp = tmp->next;
    }
}


/*
Fonction : Alloue une cellule de la table
de hachage, et qui initialise ses champs en mettant la valeur à zéro.
*/
HashCell *create_hashcell(Key *key) {
    HashCell *cell = (HashCell *) malloc(sizeof(HashCell));
    if (!verif(cell != NULL, 0)) return NULL;
    cell->key = key;
    cell->val = 0;
    return cell;
}

/*
Fonction : retourne la position
d’un  ́elément dans la table de hachage
*/
int hash_function(Key *key, int size) {
    if (!verif(key != NULL, 1)) return -1;
    return (key->val)%size;
}

/*
Fonction : cherche dans la table t s’il existe un ́elément dont la 
clé publique est key. Si l’élément a  ́eté trouvé, la 
fonction retourne sa position dans la table, sinon la
fonction retourne la position où il aurait dû être
*/
int find_position(HashTable *t, Key *key) {
    if (!verif(t != NULL && key != NULL, 1)) return -1;
    int pos = hash_function(key, t->size);
    int step = 0;
    while (t->tab[(pos + step)%(t->size)] != NULL) {
        //dans la création d'une table de hachage nous avons initialisé toutes
        //les cases à NULL donc on vérifie si la case est NULL pour savoir si
        //la clé peut occuper cette place

        if (t->tab[(pos + step)%(t->size)]->key->val == key->val &&
            t->tab[(pos + step)%(t->size)]->key->n == key->n)  {
                return (pos + step)%t->size;
        }
        if (step == t->size) {
            printf("Plus de place dans la table\n");
            return -1;
        }
        step++;
    }
    return (pos + step)%t->size;
}

/*
Fonction : créé et initialise une table de hachage de taille size contenant une cellule pour chaque clé de la liste chaînée
keys.
*/
HashTable *create_hashtable(CellKey *keys, int size) {
    HashTable *table = (HashTable *) malloc(sizeof(HashTable));
    if (!verif(table != NULL, 0)) return NULL;
    table->size = size;
    table->tab = (HashCell **) malloc(sizeof(HashCell *)*size);
    if(!verif(table->tab != NULL, 0)) {
        free(table);
        return NULL;
    }

    for (int i = 0; i < size; i++) {
        table->tab[i] = NULL;
        //initialisation des cases à NULL pour savoir si une case contient
        //déjà une clé ou pas
    }

    int pos;
    while (keys != NULL) {
        //on parcourt la liste des clefs et on l'ajoute dans la table.
        pos = find_position(table, keys->data);
        if (pos == -1) {
            printf("il n'y a plus de place dans la table\n");
            break;
        }
        table->tab[pos] = create_hashcell(keys->data);
        keys = keys->next;
    }
    return table;
}

/*
Fonction : libère une table de hachage.
*/
void delete_hashtable(HashTable *t) {
    if (!verif(t != NULL, 1)) return;
    for (int i = 0; i < t->size; i++) {
        if (t->tab[i] != NULL) {
            free(t->tab[i]);
        }
    }
    free(t->tab);
    free(t);
}

/*
Fonction : calcule le vainqueur d'une l’élection
*/
Key *compute_winner(CellProtected *decl, CellKey *candidates, 
                    CellKey *voters, int sizeC, int sizeV) {
    if (!verif(decl != NULL && candidates != NULL && voters != NULL && sizeC > 0 && sizeV > 0, 1)) return NULL;
    // on commence par créer les 2 tables de hachage pour les candidats et les votants
    HashTable *hc = create_hashtable(candidates, sizeC);
    if (!verif(hc != NULL, 0)) return NULL;
    HashTable *hv = create_hashtable(voters, sizeV);
    if (!verif(hv != NULL, 0)) {
        delete_hashtable(hc);
        return NULL;
    }
    int pos, posC;
    Key *keyC;
    while(decl != NULL) {
        // on vérifie qu'il a le droit de voter (et qu'il n'a pas déjà voté)
        pos = find_position(hv, decl->data->pKey);
        if (hv->tab[pos] != NULL) {
            if (hv->tab[pos]->val == 0) {
                keyC = str_to_key(decl->data->msg);
                // on verifie qu'il vote pour un candidat éligible
                posC = find_position(hc, keyC);
                if (hc->tab[posC] != NULL) { 
                    // une fois la véréfication faite, on comptabilise le vote
                    (hc->tab[posC]->val)++;
                    hv->tab[pos]->val = 1;
                }
                free(keyC);
            }
            
        }
        decl = decl->next;
    }
    
    //recherche du gagnant
    int max = -1; // en cas d'égalité c'est le premier candidat dans la table qui est élu 
    HashCell *vainqueur = NULL;
    //fonction classique de recherche d'un maximum dans un tableau
    for(int i = 0; i < hc->size; i++) {
        if (hc->tab[i] != NULL) {
            if (max < hc->tab[i]->val) {
                max = hc->tab[i]->val;
                vainqueur = hc->tab[i];
            }
        }
    }

    Key *res = (Key *) malloc(sizeof(Key));
    init_key(res, vainqueur->key->val, vainqueur->key->n);
    
    delete_hashtable(hv);
    delete_hashtable(hc);
    return res;
}