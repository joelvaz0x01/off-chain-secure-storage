#ifndef __CRYPTO_STORAGE_TA_H__
#define __CRYPTO_STORAGE_TA_H__

#define RSA_KEY_SIZE_BITS 2048
#define RSA_MODULUS_SIZE (RSA_KEY_SIZE_BITS / 8)
#define RSA_EXPONENT_SIZE 4
#define RSA_PUBLIC_KEY_SIZE (RSA_MODULUS_SIZE + RSA_EXPONENT_SIZE)
#define RSA_SIGNATURE_SIZE (RSA_KEY_SIZE_BITS / 8)

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 256

#define SHA256_HASH_SIZE 32

/* Only available when building the TA code */
#ifdef TEE_INTERNAL_API_H
#define RSA_KEYPAIR_STORAGE_NAME "rsaKeyPair"
#define AES_KEY_STORAGE_NAME "aesKey"

TEE_Result convert_to_hex_str(void *data, size_t data_sz, char *output_data_str, size_t output_data_str_sz);
TEE_Result compute_sha256(char *data, size_t data_sz, uint8_t *hash_output, size_t *hash_output_sz);
TEE_Result generate_rsa_key_pair(TEE_ObjectHandle *key_pair_handle);
TEE_Result generate_aes_key(TEE_ObjectHandle *key_handle);
TEE_Result get_rsa_public_key(uint8_t *public_key, size_t *public_key_len);
TEE_Result encrypt_aes_data(const char *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len);
TEE_Result decrypt_aes_data(const uint8_t *ciphertext, size_t ciphertext_len, char *plaintext, size_t *plaintext_len);
#endif /* TEE_INTERNAL_API_H */

#endif /* __CRYPTO_STORAGE_TA_H__ */
