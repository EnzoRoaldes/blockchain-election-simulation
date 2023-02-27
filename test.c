#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto.h"
#include "prime.h"
#include "vote.h"
#include "utilities.h"

//fonction donnée
void print_long_vector(long *result, int size) {
    printf("Vector : [");
    for (int i = 0; i < size; i++) {
        printf("%ld \t", result[i]);
    }
    printf("] \n");
}

void exercice2() { // main donné dans le sujet
    long p = random_prime_number(15, 16, 5000);
    long q = random_prime_number(16, 17, 5000); // on a pris 16, 17 au lieu de 15, 16
                        // car sinon on peut avoir p = q et ça ne marcherai pas.
    printf("p = %ld\nq = %ld\n", p, q);
    long n, s, u;
    generate_key_values(p, q, &n, &s, &u);
    printf("cle publique = (%ld, %ld) \n", s, n);
    printf("cle privee = (%ld, %ld) \n", u, n);
    
    char message[1000] = "Hello World";
    int len = strlen(message);

    long *crypted = encrypt(message, s, n);

    printf("Initial message : %s \n", message);
    printf("Encoded representation : \n");
    print_long_vector(crypted, len);

    char *decoded = decrypt(crypted, len, u, n);
    printf("Decoded : %s \n", decoded);

    free(decoded);
    free(crypted);
}

void exercice3() { // main donné dans le sujet, nous avons rajouté quelque free().
    char *tmpstr;
    Key *pKey = malloc(sizeof(Key));
    Key *sKey = malloc(sizeof(Key));
    init_pair_keys(pKey, sKey, 3, 7);
    printf("pKey: %lx, %lx \n", pKey->val, pKey->n);
    printf("sKey: %lx, %lx \n", sKey->val, sKey->n);
    char *chaine = key_to_str(pKey);
    printf("key_to_str: %s \n", chaine);
    Key *k = str_to_key(chaine);
    printf("str_to_key: %lx, %lx \n", k->val, k->n);

    Key *pKeyC = malloc(sizeof(Key));
    Key *sKeyC = malloc(sizeof(Key));
    init_pair_keys(pKeyC, sKeyC, 3, 7);

    char *mess = key_to_str(pKeyC);
    tmpstr = key_to_str(pKey);
    printf("%s vote pour %s\n", tmpstr, mess);
    free(tmpstr);
    Signature *sgn = sign(mess, sKey);
    printf("signature: ");
    print_long_vector(sgn->tab, sgn->taille);
    free(chaine);
    chaine = signature_to_str(sgn);
    printf("signature_to_str: %s \n", chaine);
    free(sgn->tab);
    free(sgn);
    sgn = str_to_signature(chaine);
    printf("str_to_signature: ");
    print_long_vector(sgn->tab, sgn->taille);

    Protected *pr = init_protected(pKey, mess, sgn);

    if (verify(pr)) {
        printf("Signature valide\n");
    } else {
        printf("Signature non valide\n");
    }
    free(chaine);
    chaine = protected_to_str(pr);
    printf("protected_to_str: %s\n", chaine);
    free(pr);
    pr = str_to_protected(chaine);
    tmpstr = key_to_str(pr->pKey);
    char *tmpstr2 = signature_to_str(pr->sgn);
    printf("str_to_protected: %s %s %s\n", tmpstr, pr->msg, tmpstr2);
    free(tmpstr);
    free(tmpstr2);
    if (verify(pr)) {
        printf("Signature valide\n");
    } else {
        printf("Signature non valide\n");
    }
    free(sgn->tab);
    free(sgn);
    free(pr);
    free(chaine);
    free(mess);
    free(k);
    free(pKey);
    free(sKey);
    free(pKeyC);
    free(sKeyC);
}


int main() {
    srand(time(NULL));
    printf("============ DEBUT EXERCICE 2 ===============\n");
    exercice2();
    printf("============ FIN EXERCICE 2 ===============\n");
    printf("============ DEBUT EXERCICE 3 ===============\n");
    exercice3();
    printf("============ FIN EXERCICE 3 ===============\n");
    return 0;
}