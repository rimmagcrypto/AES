#include <stdio.h>
#include <string.h>
#include "gf.h"
#include "params.h"
#include "aes_functions.h"



void print_state(unsigned char *aes_state){
    unsigned int rows_state;
    unsigned int columns_state;

    for (rows_state = 0; rows_state < NB_ROWS; rows_state++){
        for (columns_state = 0; columns_state < NB_BLOCKS; columns_state++){
            printf("%02X ", aes_state[rows_state + columns_state*NB_ROWS]);
        }
        printf("\n");
    }
    printf("\n");
}

void print_round_key(unsigned char *expanded_keys) {
    for(int round = 0; round <= NB_ROUNDS_128; round++) {
        printf("Round %2d key:\n", round);
        for(int row = 0; row < NB_ROWS; row++) {
            for(int col = 0; col < NB_BLOCKS; col++) {
                printf("%02X ", expanded_keys[round * NB_ROWS * NB_BLOCKS + col * NB_ROWS + row]);
            }
            printf("\n");
        }
        printf("\n");
    }
}


void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void aes_encryption_block(unsigned char *ciphertext, const unsigned char *plaintext, const unsigned char *key){
    unsigned char aes_state[STATE_BYTES];
    unsigned char aes_round_keys[NB_BLOCKS * NB_ROWS * (NB_ROUNDS_128+1)];
    unsigned int round;

    memcpy(aes_state, plaintext, STATE_BYTES);
    print_state(aes_state);

    KeyExpansion(aes_round_keys, key);
    print_round_key(aes_round_keys);

    AddRoundKey(aes_state, &aes_round_keys[0]);

    for(round = 1; round < NB_ROUNDS_128;round++){
        SubBytes(aes_state);
        ShiftRows(aes_state);
        MixColumns(aes_state);
        AddRoundKey(aes_state, &aes_round_keys[NB_BLOCKS*NB_ROWS*round]);
    }

    SubBytes(aes_state);
    print_state(aes_state);
    ShiftRows(aes_state);
    print_state(aes_state);
    AddRoundKey(aes_state, &aes_round_keys[NB_BLOCKS*NB_ROWS*NB_ROUNDS_128]);
    print_state(aes_state);
    memcpy(ciphertext, aes_state, STATE_BYTES);
}


void aes_decryption_block(unsigned char *plaintext, const unsigned char *key, const unsigned char *ciphertext){
    unsigned char aes_state[STATE_BYTES];
    unsigned char aes_round_keys[NB_BLOCKS * NB_ROWS * (NB_ROUNDS_128+1)];
    unsigned int round;

    memcpy(aes_state, ciphertext, STATE_BYTES);
    print_state(aes_state);

    KeyExpansion(aes_round_keys, key);
    print_round_key(aes_round_keys);

    AddRoundKey(aes_state, &aes_round_keys[NB_BLOCKS*NB_ROWS*NB_ROUNDS_128]);
    InvShiftRows(aes_state);
    InvSubBytes(aes_state);

    for(round = NB_ROUNDS_128-1; round > 0; round--){
        AddRoundKey(aes_state, &aes_round_keys[NB_BLOCKS*NB_ROWS*round]);
        InvMixColumns(aes_state);
        InvShiftRows(aes_state);
        InvSubBytes(aes_state);
    }

    AddRoundKey(aes_state, &aes_round_keys[0]);
    print_state(aes_state);
    memcpy(plaintext, aes_state, STATE_BYTES);
}
