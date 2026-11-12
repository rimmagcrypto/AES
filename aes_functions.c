#include <string.h>

#include "aes_functions.h"
#include "params.h"
#include "gf.h"


void SubBytes(unsigned char *state){
    unsigned int i;
    for (i = 0; i < STATE_BYTES; i++)
        state[i] = S_BOX[state[i]];
}



void InvSubBytes(unsigned char *state){
    unsigned int i;
    for (i = 0; i < STATE_BYTES; i++)
        state[i] = INV_S_BOX[state[i]];
}


void ShiftRows(unsigned char *state){
    unsigned char tmp;

    //Décalage de 1 octet vers la gauche
    tmp = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = tmp;

    //Décalage de 2 octets vers la gauche
    tmp = state[2];
    state[2]  = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6]  = state[14];
    state[14] = tmp;

    //Décalage de 3 octets vers la gauche
    tmp = state[3];
    state[3]  = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = tmp;

}


void InvShiftRows(unsigned char *state) {
    unsigned char tmp;

    // Ligne 1 : décalage de 1 vers la droite
    tmp = state[13];
    state[13] = state[9];
    state[9]  = state[5];
    state[5]  = state[1];
    state[1]  = tmp;

    // Ligne 2 : décalage de 2 vers la droite
    tmp = state[2];
    state[2]  = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6]  = state[14];
    state[14] = tmp;

    // Ligne 3 : décalage de 3 vers la droite (ou 1 vers la gauche)
    tmp = state[3];
    state[3]  = state[7];
    state[7]  = state[11];
    state[11] = state[15];
    state[15] = tmp;
}


void MixColumns(unsigned char *state){
    unsigned int j;

    for (j = 0; j < NB_BLOCKS; j++){
        unsigned char tmp[4];
        memcpy(tmp, &state[NB_ROWS*j], 4);

        state[NB_ROWS*j] = multiply_bytes(tmp[0],0x02) ^ multiply_bytes(tmp[1],0x03) ^ tmp[2] ^ tmp[3];
        state[NB_ROWS*j + 1] = tmp[0] ^ multiply_bytes(tmp[1],0x02) ^ multiply_bytes(tmp[2],0x03) ^ tmp[3];
        state[NB_ROWS*j + 2] = tmp[0] ^ tmp[1] ^ multiply_bytes(tmp[2],0x02) ^ multiply_bytes(tmp[3],0x03);
        state[NB_ROWS*j + 3] = multiply_bytes(tmp[0],0x03) ^ tmp[1] ^ tmp[2] ^ multiply_bytes(tmp[3],0x02);

    }

}

void InvMixColumns(unsigned char *state){
    unsigned int j;

    for (j = 0; j < NB_BLOCKS; j++){
        unsigned char tmp[4];
        memcpy(tmp, &state[NB_ROWS*j], 4);

        state[NB_ROWS*j] = multiply_bytes(tmp[0],0x0E) ^ multiply_bytes(tmp[1],0x0B) ^
                           multiply_bytes(tmp[2],0x0D) ^ multiply_bytes(tmp[3],0x09);
        state[NB_ROWS*j + 1] = multiply_bytes(tmp[0],0x09) ^ multiply_bytes(tmp[1],0x0E) ^
                               multiply_bytes(tmp[2],0x0B) ^ multiply_bytes(tmp[3],0x0D);
        state[NB_ROWS*j + 2] = multiply_bytes(tmp[0],0x0D) ^ multiply_bytes(tmp[1],0x09) ^
                               multiply_bytes(tmp[2],0x0E) ^ multiply_bytes(tmp[3],0x0B);
        state[NB_ROWS*j + 3] = multiply_bytes(tmp[0],0x0B) ^ multiply_bytes(tmp[1],0x0D) ^
                               multiply_bytes(tmp[2],0x09) ^ multiply_bytes(tmp[3],0x0E);
    }

}

void AddRoundKey(unsigned char *state, const unsigned char *round_key){
    unsigned int rows_state;
    unsigned int columns_state;
    for (rows_state = 0; rows_state < NB_ROWS; rows_state++)
        for (columns_state = 0; columns_state < NB_BLOCKS; columns_state++)
            state[rows_state + columns_state*NB_ROWS] ^= round_key[rows_state + columns_state*NB_ROWS];
}

void SubWord(unsigned char word[4]) {
    unsigned int i;
    for (i = 0; i < 4; i++)
        word[i] = S_BOX[word[i]];
}

void RotWord(unsigned char word[4]){
    unsigned char tmp = word[0];

    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;

}

void KeyExpansion(unsigned char *expanded_keys, const unsigned char *key){
    unsigned int i, j;
    unsigned char tmp[4];

    // Copie clé initiale (KEY_SIZE_128 = 4 mots pour AES-128)
    for(i = 0; i < KEY_SIZE_128; i++){
        memcpy(&expanded_keys[NB_ROWS*i], &key[NB_ROWS*i], NB_ROWS);
    }

    for(i = KEY_SIZE_128; i < NB_BLOCKS*(NB_ROUNDS_128+1); i++){
        // tmp = mot précédent
        memcpy(tmp, &expanded_keys[NB_ROWS*(i-1)], NB_ROWS);

        if (i % KEY_SIZE_128 == 0){
            RotWord(tmp);   // rotation circulaire
            SubWord(tmp);   // substitution via S-box
            tmp[0] ^= RCON[i / KEY_SIZE_128]; // applique Rcon seulement sur le 1er octet
        }

        // XOR avec le mot NB_ROWS précédents
        for(j = 0; j < NB_ROWS; j++){
            expanded_keys[NB_ROWS*i + j] = expanded_keys[NB_ROWS*(i - KEY_SIZE_128) + j] ^ tmp[j];
        }
    }
}
