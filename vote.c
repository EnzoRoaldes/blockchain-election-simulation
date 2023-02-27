#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include "crypto.h"
#include "prime.h"
#include "vote.h"
#include "utilities.h"

/*
Fonction : initialise une clé déjà allouée.
*/
void init_key(Key* key, long val, long n) {
    if (!verif(key != NULL, 1)) return;
    key->val = val;
    key->n = n;
}

/*
Fonction : affiche une clé non NULL
*/
void afficher_key(Key *key) {
    if (!verif(key != NULL, 1)) return;
    printf("Clé = (%ld,%ld)\n", key->val, key->n);
}

/*
Fonction : utilise le protocole RSA pour générer une clé publique pKey = (s, n) et une 
clé secrète sKey = (u, n).
Commentaire : on génère deux nombres premiers p et q différents, puis grâce à la fonction generate_key_values()
on génère les nombres s, u et n à partir de p et q. Puis on initialise les deux clés avec leurs valeurs
respectives.
*/
void init_pair_keys(Key *pKey, Key *sKey, long low_size, long up_size) {
    if (!verif(low_size >= 0 && up_size > low_size, 1)) return;
    long p = random_prime_number(low_size, up_size, 5000);
    long q = random_prime_number(low_size+1, up_size, 5000); //on rajoute +1 car
                        //sinon il est très probable d'avoir p = q et les fonctions ne marcheront pas
                        //car on doit avoir p différent de q. Avec le +1 il est peu probable qu'on
                        //ai p = q
    if (p == q) {
        printf("Attention les nombres premiers générés p et q sont égaux (p == q)\n");
    }
    long n, s, u;
    generate_key_values(p, q, &n, &s, &u);
    init_key(pKey, s, n);
    init_key(sKey, u, n);
}

/*
Fonction : convertit un nombre décimal en nombre hexadécimal sous frome d'une chaîne de caractères.
Commentaire : on traîte chaque puissance de 16 une à une et on convertit le
multiple de cette puissance en nombre ou en lettre selon sa valeur.
*/
char *nb_to_hexa_str(long val) {
    if (!verif(val >= 0, 1)) return NULL;
    char *res = (char *) malloc(sizeof(char)*256);
    if (!verif(res != NULL, 0)) return NULL;
    if (val == 0) {
        res[0] = '0';
        res[1] = '\0';
        return res;
    }
    int cpt = 0;
    long tmp;
    while (val > 0) {
        tmp = (long) ((val/16.0 - floor(val/16.0)) * 16.0);
        //on prend la partie décimal de la division de val par 16 puis on la multiplie par 16
        //afin d'obtenir le multiple de la puissance de 16 en question (cpt).
        val = floor(val/16.0);
        //la partie décimale ayant été traîtée, on l'enlève grâce au floor, pour recommencer le
        //processus pour la puissance de 16 suivante.
        if (tmp < 10) {
            res[cpt] = tmp + '0';
        } else {
            res[cpt] = 'a' + tmp - 10; //-10 car on veut 'a' si tmp = 10, 'b' si tmp = 11 etc.. donc 
                                       //tmp-10 pour repartir de 0 et avoir 'a' ou 'b' etc..
        }
        cpt++;
    }
    //la chaîne du nombre hexadécimal est générée dans le sens inverse donc on la retourne dans le bon sens.
    for (int i = 0; i < cpt/2; i++) {
        char c = res[i];
        res[i] = res[cpt-i-1];
        res[cpt-i-1] = c;
    }
    res[cpt] = '\0';
    return res;
}

/*
Fonction : retourne la clé sous la forme d'une chaîne où ses champs val et n sont sous forme hexadécimale.
Commentaire : on écrit la chaîne sous le format demandé (x,y) avec x et y les conversions respectives de
val et n en hexadécimal. On utilise strcat() pour concaténer les chaînes obtenues.
*/
char *key_to_str(Key *key) {
    if (!verif(key != NULL, 1)) return NULL;
    char *res = (char *) malloc(sizeof(char)*256);
    if (!verif(res != NULL, 0)) return NULL;
    res[0] = '(';
    res[1] = '\0';
    char *hex_val = nb_to_hexa_str(key->val);
    char *hex_n = nb_to_hexa_str(key->n);
    if(!verif(strcat(res, hex_val) != NULL, 3)) return NULL;
    if(!verif(strcat(res, ",\0") != NULL, 3)) return NULL;
    if(!verif(strcat(res, hex_n) != NULL, 3)) return NULL;
    if(!verif(strcat(res, ")\0") != NULL, 3)) return NULL;
    free(hex_val);
    free(hex_n);
    return res;
}

/*
Fonction : on transforme une chaîne de caractère sous le format (x,y) en une clé où 
x et y sont des nombres hexadécimaux/
Commentaire : on parcourt la chaîne et on convertit x et y en nombre décimaux en 
parcourant le chaîne caractère par caractère.
*/
Key *str_to_key(char *str) {
    if (!verif(str != NULL, 1)) return NULL;
    Key *key = (Key *) malloc(sizeof(Key));
    if (!verif(key != NULL, 0)) return NULL;
    long val = 0;
    int i = 1; //on saute la parenthèse du début
    while (str[i] !=  ',') { //on stop à la virgule pour avoir x
        val = val*16;
        //x est sous la forme x = a_n*16^n + ... + a_0*16^0
        //comme on commence par la puissance la plus elevée
        //il faut augmenter les puissances de 16 à chaque tour pour que
        //le 1er terme ait sa puissance à n, le 2ième à n-1 etc..
        if ('0' <= str[i] && str[i] <= '9') {
            val += str[i] - '0'; //on ajoute a_i
        } else {
            val += str[i] - 'a' + 10; //de même avec le +10 car 'a' == 10 + 0, 'b' = 10 + 1 etc..
        }
        i++;
    }
    i++;
    long n = 0;
    //on procède de même pour y.
    while (str[i] !=  ')') {
        n = n*16;
        if ('0' <= str[i] && str[i] <= '9') {
            n += str[i] - '0';
        } else {
            n += str[i] - 'a' + 10;
        }
        i++;
    }
    init_key(key, val, n);
}

/*
Fonction : alloue et initialise une signature.
*/
Signature *init_signature(long *content, int size) {
    Signature *signature = (Signature *) malloc(sizeof(Signature));
    if (!verif(signature != NULL, 0)) return NULL;
    signature->tab = content;
    signature->taille = size;
    return signature;
}

/*
Fonction : créer une signature à partir du message mess et de la clé privée sKey.
Commentaire : on crypte le message mess avec encrypt grâce à sKey.
*/
Signature *sign(char *mess, Key *sKey) {
    if (!verif(mess != NULL, 1)) return NULL;
    if (!verif(sKey != NULL, 1)) return NULL;
    return init_signature(
        encrypt(mess, sKey->val, sKey->n), 
        strlen(mess));
}

//fonction donnée
char *signature_to_str(Signature *sgn) {
    if (!verif(sgn != NULL, 1)) return NULL;
    char *result = malloc(100*sgn->taille*sizeof(char)); //on a mis *100 car *10 n'était pas assez grand pour des grands nombres premiers
    if (!verif(result != NULL, 0)) return NULL;
    result[0] = '#';
    int pos = 1;
    char buffer[1024];
    for (int i = 0; i < sgn->taille; i++) {
        sprintf(buffer, "%lx", sgn->tab[i]);
        for (int j = 0; j < strlen(buffer); j++) {
            result[pos] = buffer[j];
            pos++;
        }
        result[pos] = '#';
        pos++;
    }
    result[pos] = '\0';
    result = realloc(result, (pos+1)*sizeof(char));
    return result;
}

//fonction donnée
Signature *str_to_signature(char *str) {
    if (!verif(str != NULL, 1)) return NULL;
    int len = strlen(str);
    long *content = (long *) malloc(sizeof(long) * len);
    if (!verif(content != NULL, 0)) return NULL;
    int num = 0;
    char buffer[1024];
    int pos = 0;
    for (int i = 0; i < len; i++) {
        if (str[i] != '#') {
            buffer[pos] = str[i];
            pos++;
        } else {
            if (pos != 0) {
                buffer[pos] = '\0';
                sscanf(buffer, "%lx", &(content[num]));
                num++;
                pos = 0;
            }
        }
    }
    content = realloc(content, num*sizeof(long));
    return init_signature(content, num);
}

/*
Fonction : alloue et initialise un Protected.
*/
Protected *init_protected(Key *pKey, char *mess, Signature *sgn) {
    Protected *res = (Protected *) malloc(sizeof(Protected));
    if (!verif(res != NULL, 0)) return NULL;
    res->pKey = pKey;
    res->msg = mess;
    res->sgn = sgn;
    return res;
}

/*
Fonction : vérifie que la signature contenue dans
pr correspond bien au message et à la personne contenus dans pr.
*/
int verify(Protected *pr) {
    if (!verif(pr != NULL, 1)) return 0;
    char *decr = decrypt(pr->sgn->tab, pr->sgn->taille, pr->pKey->val, pr->pKey->n);
    int res = !strcmp(pr->msg, decr);
    free(decr);
    return res;
}

/*
Fonction : converti un protected sous la forme d'une chaîne de caractère sous la forme :
"cle_publique message signature", tous séparés par un espace.
Commentaire : on utilise les fonctions key_to_str() et signature_to_str() pour convertir
la clé et la signature en str et on utilise strcat() pour concaténer les différentes chaînes.
*/
char *protected_to_str(Protected *pr) {
    if (!verif(pr != NULL, 1)) return NULL;
    char *res = (char *) malloc(sizeof(char)*1024);
    if (!verif(res != NULL, 0)) return NULL;
    res[0] = '\0';
    char *str_key = key_to_str(pr->pKey);
    char *str_sgn = signature_to_str(pr->sgn);
    if (!verif(strcat(res, str_key) != NULL, 3)) return NULL;
    if (!verif(strcat(res, " \0") != NULL, 3)) return NULL;
    if (!verif(strcat(res, pr->msg) != NULL, 3)) return NULL;
    if (!verif(strcat(res, " \0") != NULL, 3)) return NULL;
    if (!verif(strcat(res, str_sgn) != NULL, 3)) return NULL;
    free(str_key);
    free(str_sgn);
    return res;
}

/*
Fonction : converti une chaîne sous la forme "cle_publique message signature", en un Protected.
Commentaire : on utilise sscanf pour séparer la chaîne str en les 3 chaînes voulues puis on reconverti
chacune des chaînes dans le format voulu (Key, char* et Signature).
*/
Protected *str_to_protected(char *str) {
    if (!verif(str != NULL, 1)) return NULL;
    char strKey[256];
    char strMsg[256];
    char strSgn[512];
    if (!verif(sscanf(str, "%s %s %s", strKey, strMsg, strSgn) == 3, 2)) {
        return NULL;
    }
    return init_protected(str_to_key(strKey), strdup(strMsg), str_to_signature(strSgn));
}