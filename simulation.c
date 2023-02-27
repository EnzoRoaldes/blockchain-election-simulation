#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto.h"
#include "prime.h"
#include "vote.h"
#include "syst_central.h"
#include "utilities.h"

void exercice5() {
    generate_random_data(10, 4); //10 citoyens, 4 candidats
    CellKey *LCK_citoyens = read_public_keys("keys.txt");
    CellKey *LCK_candidats = read_public_keys("candidates.txt");
    printf("Clés des citoyens :\n");
    print_list_keys(LCK_citoyens);
    printf("-------------------------------\n");
    printf("Clés des candidats :\n");
    print_list_keys(LCK_candidats);
    delete_list_keys(LCK_citoyens);
    delete_list_keys(LCK_candidats);

    CellProtected *LCP = read_protected("declarations.txt");

    //on va ajouter un fradeur à la liste des déclarations
    Key *fraudeur_key = (Key *) malloc(sizeof(Key));
    init_key(fraudeur_key, 2304, 321);
    long tmp[10] = {1, 5, 2, 64, 13, 154, 25667, 212, 143, 45};
    long *tab = (long *) malloc(sizeof(long)*10);
    for (int i = 0; i < 10; i++) {
        tab[i] = tmp[i];
    }
    Signature *fraudeur_sgn = init_signature(tab, 10);
    Protected *fraudeur = init_protected(fraudeur_key, strdup("je suis un fraudeur"), fraudeur_sgn);
    ajoute_protected_deb(&LCP, fraudeur);

    printf("Liste des déclarations après ajout d'un fraudeur :\n");
    print_list_protecteds(LCP);
    printf("Suppression fraude...\n");
    printf("Liste des déclarations après suppression du fraudeur :\n");
    supp_fraude(&LCP);
    print_list_protecteds(LCP); //on a supprimé les fraudes, on voit que le fradeur a bien été enlevé
    delete_list_protected(LCP);
}

void exercice6() {
    int nb_citoy = 10;
    int nb_candid = 3;
    generate_random_data(nb_citoy, nb_candid);
    CellKey *LCK_citoyens_ = read_public_keys("keys.txt");
    CellKey *LCK_candidats_ = read_public_keys("candidates.txt");
    CellProtected *LCP_ = read_protected("declarations.txt");
    supp_fraude(&LCP_); //supp_fraude() car l'énnoncé suppose que
    //la liste de déclaration donnée dans compute_winner() est valide.

    Key *vainqueur = compute_winner(LCP_, LCK_candidats_,
        LCK_citoyens_, nb_candid, nb_citoy);
    char *str_vainq = key_to_str(vainqueur);
    printf("Clé du gagnant : %s\n", str_vainq);

    free(str_vainq);
    free(vainqueur);
    delete_list_keys(LCK_citoyens_);
    delete_list_keys(LCK_candidats_);
    delete_list_protected(LCP_);
}


int main() {
    srand(time(NULL));
    printf("============ DEBUT EXERCICE 5 ===============\n");
    exercice5();
    printf("============ FIN EXERCICE 5 ===============\n");
    printf("============ DEBUT EXERCICE 6 ===============\n");
    exercice6();
    printf("============ FIN EXERCICE 6 ===============\n");
    return 0;
}