#include <stdio.h>
#include "utilities.h"

//tableau qui contient les messages d'erreurs
char tab_msg_errs[10][256] = {"Erreur d'allacation.",
                                "Erreur valeur en paramètre non valide.",
                                "Erreur format chaîne non valide."
                                "Erreur fonctions string, fichier... (strcat(), fgets()...)"};

/* Fonction : fonction de vérification d'une condition qu'on passe en paramètre et qui affiche
le message d'erreur voulu avec l'indice i si la condition n'est pas vérifiée (== 0)
*/
int verif(int cond, int i) {
    if (cond == 0) {
        printf("%s\n", tab_msg_errs[i]);
        return 0;
    }
    return 1;
}