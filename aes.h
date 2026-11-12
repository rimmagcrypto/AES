#ifndef AES_H
#define AES_H

void print_state(unsigned char *aes_state);
void print_round_key(unsigned char *expanded_keys);


void aes_encryption_block(unsigned char *ciphertext, const unsigned char *plaintext, const unsigned char *key);

void aes_decryption_block(unsigned char *plaintext, const unsigned char *key, const unsigned char *ciphertext);
#endif // AES_H
