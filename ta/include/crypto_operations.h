#ifndef __CRYPTO_STORAGE_TA_H__
#define __CRYPTO_STORAGE_TA_H__

#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

TEE_Result compute_sha256(char *json_data, size_t json_data_sz, char *hash_output, size_t *hash_output_sz);
TEE_Result generate_ed25519_key_pair(TEE_ObjectHandle *key_pair_handle);
TEE_Result generate_aes_key(TEE_ObjectHandle *key_handle);
TEE_Result get_code_attestation(void *signature, size_t *sig_len);
TEE_Result get_ed25519_public_key(char *public_key, size_t *public_key_len);
TEE_Result encrypt_aes_data(const char *plaintext, size_t plaintext_len, char *ciphertext, size_t *ciphertext_len);
TEE_Result decrypt_aes_data(const char *ciphertext, size_t ciphertext_len, char *plaintext, size_t *plaintext_len);

#endif /* __CRYPTO_STORAGE_TA_H__ */
