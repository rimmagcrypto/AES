#ifndef PARAMS_H
#define PARAMS_H

// -------------------------
// Taille de l'état AES
// -------------------------

#define NB_BLOCKS 4
#define NB_ROWS   4
#define STATE_BYTES NB_BLOCKS * NB_ROWS

// -------------------------
// Tailles des clés (en mots de 4 octets)
// -------------------------
#define KEY_SIZE_128 4  // 16 octets
#define KEY_SIZE_192 6  // 24 octets
#define KEY_SIZE_256 8  // 32 octets
// Taille de la clé en octets
#define KEY_BYTES(size_macro) ((size_macro) * WORD_SIZE)

// -------------------------
// Nombre de tours (rounds)
// -------------------------
#define NB_ROUNDS_128 10
#define NB_ROUNDS_192 12
#define NB_ROUNDS_256 14

// -------------------------
// Taille d'un mot en octets
// -------------------------
#define WORD_SIZE 4


#endif
