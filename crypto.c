#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "prime.h"
#include "utilities.h"

//fonction donnée
long extended_gcd(long s, long t, long *u, long *v) {
    if (t == 0) {
        *u = 1;
        *v = 0;
        return s;
    }
    long uPrim, vPrim;
    long gcd = extended_gcd(t, s % t, &uPrim, &vPrim);
    *u = vPrim;
    *v = uPrim-(s/t)*vPrim;
    return gcd;
}

/*
Fonction : permet de générer la clé publique pKey = (s, n) et la clé secrète sKey = (u, n), à partir
des nombres premiers p et q, en suivant le protocole RSA.
Commentaire : on a appliqué le protocole demandé dans l'ennoncé afin de générer les clés.
*/
void generate_key_values(long p, long q, long *n, long *s, long *u) {
    *n = p*q;
    long t = (p-1)*(q-1);
    *s = rand()%(t-2)+2;
    long v;
    while (extended_gcd(*s, t, u, &v) != 1) {
        *s = rand()%(t-2)+2;
    }
    *u = (*u + t) % t; //parfois u est négatif donc on le remet positif
}

/*
Fonction : chiffre la chaîne de caractères chaine avec la clé publique pKey = (s, n)
Commentaire : on parcourt chaine caractère par caractère et on convertit chaque caractère
en int avec son code ASCII puis on le chiffre à l'aide de modpow et de la clé publique.
*/
long *encrypt(char *chaine, long s, long n) {
    if (!verif(chaine != NULL, 1)) return NULL;
    int taille = strlen(chaine);
    long *tab = (long *) malloc(sizeof(long)*taille);
    if (!verif(tab != NULL, 0)) return NULL;
    for (int i = 0; i < taille; i++) {
        tab[i] = modpow((long) chaine[i], s, n);
    }
    return tab;
}

/*
Fonction : déchiffre crypted en un message à l’aide de la clé secrète sKey = (u, n)
Commentaire : on parcourt le tableau crypted et on déchiffre chaque long du tableau
en le caractère qui correspond à l'aide de modpow et de la clé secrète.
*/
char *decrypt(long *crypted, int size, long u, long n) {
    if (!verif(crypted != NULL && size >= 0, 1)) return NULL;
    char *msg = (char *) malloc(sizeof(char)*(size+1)); //+1 pour le '\0'
    if (!verif(msg != NULL, 0)) return NULL;
    for (int i = 0; i < size; i++) {
        msg[i] = modpow(crypted[i], u, n);
    }
    msg[size] = '\0';
    return msg;
}