#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "block.h"
#include "vote.h"
#include "syst_central.h"
#include "utilities.h"

void exercice8() { //tests pour compute_proof_of_work()
    generate_random_data(5, 2);
    CellProtected *LCP = read_protected("declarations.txt");

    clock_t temps_initial;
    clock_t temps_final;
    double temps_cpu = 0;
    FILE *f = fopen("temps_compute_proof.txt", "w");

    Key *key = (Key *) malloc(sizeof(Key));
    init_key(key, 101, 5001);
    Block *b = creer_block(key, LCP, "gfhfhgfc", "blabla", 50);

    //Test écriture et lecture d'un block dans un fichier
    ecrire_block(b, "block.txt");
    Block *l_b = lire_block("block.txt");
    printf("%s\n\n\n%s\n", block_to_str(b), block_to_str(l_b));
    delete_block(l_b, 1);

    //Test temps fonction compute_proof_of_work()
    int nb_test = 20;
    int d = 0;
    while (temps_cpu/nb_test < 10) {
        temps_initial = clock();
        for (int i = 0; i < nb_test; i++) {
            compute_proof_of_work(b, d);
        }
        temps_final = clock();
        temps_cpu = ((double) (temps_final - temps_initial)) / CLOCKS_PER_SEC;
        printf("d = %d, tmps = %f\n", d, temps_cpu/nb_test);
        fprintf(f, "%d %f\n", d, temps_cpu/nb_test);
        d++;
    }
    delete_block(b, 1);
    fclose(f);
}

void exercice9() {
    int nb_candid = 5;
    int nb_citoy = 1000;
    generate_random_data(nb_citoy, nb_candid);
    CellKey *LCK_citoyens = read_public_keys("keys.txt");
    CellKey *LCK_candidats = read_public_keys("candidates.txt");
    CellProtected *LCP = read_protected("declarations.txt");
    // On considère pour simplifier qu'il n'y a qu'un seul volontaire (le premier citoyen)
    Key *volontaire = LCK_citoyens->data;

    Block *b;
    CellTree *child;
    int N = 10;
    int d = 2;
    CellTree *tree = NULL;
    int i = 1;
    char nom_f[64];
    int nb_f = 1;
    CellProtected *tmp = LCP;
    while(tmp != NULL) {
        submit_vote(tmp->data);
        if (i == N) {
            create_valid_block(&tree, volontaire, d);
            sprintf(nom_f, "./Blockchain/Block%d.txt", nb_f);
            add_block(d, nom_f);
            nb_f++;
            i = 0;
        }
        i++;
        tmp = tmp->next;
    }

    print_tree(tree);
    CellTree *res = read_tree();
    print_tree(res);
    
    //ajout d'un fradeur dans l'arbre res
    CellProtected *LCP_fraude = NULL;
    Key *fraudeur_key = (Key *) malloc(sizeof(Key));
    init_key(fraudeur_key, 2304, 321);
    long tmptab[10] = {1, 5, 2, 64, 13, 154, 25667, 212, 143, 45};
    long *tab = (long *) malloc(sizeof(long)*10);
    for (int i = 0; i < 10; i++) {
        tab[i] = tmptab[i];
    }
    Signature *fraudeur_sgn = init_signature(tab, 10);
    Protected *fraudeur = init_protected(fraudeur_key, strdup("je suis un fraudeur"), fraudeur_sgn);
    ajoute_protected_deb(&LCP_fraude, fraudeur);
    Block *block_fraude = creer_block(fraudeur_key, LCP_fraude, "fraude", "fraude", 23098);
    add_child(res, create_node(block_fraude));
    printf("\nArbre après ajout fraude...\n");
    print_tree(res);
    
    
    Key *vainqueur = compute_winner_BT(res, LCK_candidats, LCK_citoyens, nb_candid, nb_citoy);
    char *str_vainq = key_to_str(vainqueur);
    printf("Clé du gagnant : %s\n", str_vainq);
    free(str_vainq);
    free(vainqueur);

    delete_list_protected(LCP_fraude);

    delete_list_keys(LCK_citoyens);
    delete_list_keys(LCK_candidats);
    delete_list_protected(LCP);
    delete_tree(tree, 1);
    delete_tree(res, 0);
}

int main() {
    srand(time(NULL));
    printf("============ DEBUT EXERCICE 8 ===============\n");
    exercice8();
    printf("============ FIN EXERCICE 8 ===============\n");
    printf("============ DEBUT EXERCICE 9 ===============\n");
    exercice9();
    printf("============ FIN EXERCICE 9 ===============\n");
    return 0;
}