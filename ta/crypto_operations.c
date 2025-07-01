#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <crypto_operations_ta.h>
#include <secure_storage_ta.h>

/**
 * Compute SHA256 hash of the data
 *
 * This function computes the SHA256 hash of the provided data and stores the result in the output buffer.
 * It uses the TEE API to allocate a digest operation, update it with the data, and finalize the digest.
 * The output buffer must be large enough to hold the SHA256 hash (32 bytes).
 *
 * @param data Pointer to the data to be hashed
 * @param data_sz Size of the data
 * @param hash_output Pointer to the output buffer for the hash
 * @param hash_output_sz Size of the output buffer, will be updated with actual size
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result compute_sha256(char *data, size_t data_sz, char *hash_output, size_t *hash_output_sz)
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;

    /* Check if the output buffer is large enough */
    if (*hash_output_sz < SHA256_HASH_SIZE)
    {
        EMSG("Output buffer is too small, expected size: %u bytes", SHA256_HASH_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Allocate operation for SHA256 */
    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate operation, res=0x%08x", res);
        return res;
    }

    /* Initialize the digest operation */
    TEE_DigestUpdate(op, data, data_sz);

    /* Finalize the digest and get the output */
    res = TEE_DigestDoFinal(op, NULL, 0, hash_output, (uint32_t *)hash_output_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to finalize digest, res=0x%08x", res);
        goto exit;
    }

exit:
    TEE_FreeOperation(op);
    return res;
}

/**
 * Generate or get RSA key pair and store it in secure storage
 *
 * This function checks if an RSA key pair already exists in secure storage.
 * If RSA key pair exists, it opens the persistent object and returns its handle.
 * If not, it generates a new RSA key pair and persists it in secure storage.
 * The key pair is generated with a default exponent and a key size of RSA_KEY_SIZE_BITS.
 *
 * @param key_pair_handle Pointer to the handle of the RSA key pair object
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result generate_rsa_key_pair(TEE_ObjectHandle *key_pair_handle)
{
    TEE_Result res;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ;
    TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;
    TEE_ObjectHandle pubkey_transient = TEE_HANDLE_NULL;

    /* Try to open existing key pair */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,              /* storageID */
        RSA_KEYPAIR_STORAGE_NAME,         /* objectID */
        strlen(RSA_KEYPAIR_STORAGE_NAME), /* objectIDLen */
        flags,                            /* flags */
        key_pair_handle                   /* object */
    );
    if (res == TEE_SUCCESS)
    {
        DMSG("RSA key pair already exists in persistent storage");
        return TEE_SUCCESS;
    }
    if (res != TEE_ERROR_ITEM_NOT_FOUND)
    {
        EMSG("Failed to open RSA key pair: 0x%08x", res);
        return res;
    }

    DMSG("Generating new RSA key pair");

    /* Allocate RSA keypair transient object */
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA_KEY_SIZE_BITS, &transient_key);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate RSA key pair object: 0x%08x", res);
        return res;
    }

    /* Generate key pair with default exponent */
    res = TEE_GenerateKey(transient_key, RSA_KEY_SIZE_BITS, NULL, 0);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to generate RSA key pair: 0x%08x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    /* Persist the key pair */
    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,              /* storageID */
        RSA_KEYPAIR_STORAGE_NAME,         /* objectID */
        strlen(RSA_KEYPAIR_STORAGE_NAME), /* objectIDLen */
        flags,                            /* flags */
        transient_key,                    /* attributes */
        NULL, 0,                          /* initialData , initialDataLen */
        key_pair_handle                   /* object */
    );
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to persist RSA key pair: 0x%08x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    TEE_FreeTransientObject(pubkey_transient);

    DMSG("RSA key pair and public key successfully generated and stored");
    return TEE_SUCCESS;
}

/**
 * Generate a new AES key and store it in secure storage
 *
 * This function checks if an AES key already exists in secure storage.
 * If the AES key exists, it opens the persistent object and returns its handle.
 * If not, it generates a new AES key and persists it in secure storage.
 * The AES key is generated with a size defined by AES_KEY_SIZE.
 *
 * @param key_handle Pointer to the handle of the AES key object
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result generate_aes_key(TEE_ObjectHandle *key_handle)
{
    TEE_Result res;
    TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;
    TEE_ObjectHandle persistent_key = TEE_HANDLE_NULL;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ; /* we only need read access */

    /* Verify if the AES key already exists in secure storage */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,          /* storageID */
        AES_KEY_STORAGE_NAME,         /* objectID */
        strlen(AES_KEY_STORAGE_NAME), /* objectIDLen */
        flags,                        /* flags */
        key_handle                    /* object */
    );
    if (res == TEE_SUCCESS)
    {
        DMSG("AES key retrieved from persistent storage");
        return TEE_SUCCESS;
    }
    if (res != TEE_ERROR_ITEM_NOT_FOUND)
    {
        EMSG("Failed to open AES key object: 0x%08x", res);
        return res;
    }

    /* Key doesn't exist, generate a new one */
    DMSG("Generating new AES key");

    /* Allocate a transient object for AES */
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, AES_KEY_SIZE, &transient_key);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate transient object for AES, res=0x%08x", res);
        return res;
    }

    /* Generate a random AES key */
    res = TEE_GenerateKey(transient_key, AES_KEY_SIZE, NULL, 0);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to generate AES key, res=0x%08x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    /* Store the AES key in secure storage */
    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,          /* storageID */
        AES_KEY_STORAGE_NAME,         /* objectID */
        strlen(AES_KEY_STORAGE_NAME), /* objectIDLen */
        flags,                        /* flags */
        transient_key,                /* attributes */
        NULL, 0,                      /* initialData , initialDataLen */
        &persistent_key               /* object */
    );

    TEE_FreeTransientObject(transient_key);

    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to store AES key, res=0x%08x", res);
        return res;
    }

    *key_handle = persistent_key;

    DMSG("AES key successfully generated and stored");
    return TEE_SUCCESS;
}

/**
 * Retrieve the public key of the RSA key pair stored in secure storage
 *
 * This function opens the persistent RSA key pair object and retrieves the modulus and public exponent.
 * It then combines them into a single public key buffer.
 * The public key is stored in the format: [modulus][exponent].
 * The public key buffer must be large enough to hold the modulus and exponent.
 *
 * @param public_key Buffer to store the public key
 * @param public_key_len Pointer to size of public key buffer; updated with actual public key length
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result get_rsa_public_key(char *public_key, size_t *public_key_len)
{
    TEE_Result res;
    TEE_ObjectHandle pubkey_handle = TEE_HANDLE_NULL;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ;
    char modulus[RSA_MODULUS_SIZE];
    char exponent[RSA_EXPONENT_SIZE];
    uint32_t mod_len = sizeof(modulus);
    uint32_t exp_len = sizeof(exponent);

    /* Check if the public key buffer is large enough */
    if (*public_key_len < RSA_PUBLIC_KEY_SIZE)
    {
        EMSG("Public key buffer too small, expected size: %u bytes", RSA_PUBLIC_KEY_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Open the persistent RSA key pair */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,              /* storageID */
        RSA_KEYPAIR_STORAGE_NAME,         /* objectID */
        strlen(RSA_KEYPAIR_STORAGE_NAME), /* objectIDLen */
        flags,                            /* flags */
        &pubkey_handle                    /* object */
    );
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to open RSA key pair for public key retrieval, res=0x%08x", res);
        return res;
    }

    /* Read modulus */
    res = TEE_GetObjectBufferAttribute(pubkey_handle, TEE_ATTR_RSA_MODULUS, modulus, &mod_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get modulus: 0x%08x", res);
        TEE_CloseObject(pubkey_handle);
        return res;
    }

    /* Read public exponent */
    res = TEE_GetObjectBufferAttribute(pubkey_handle, TEE_ATTR_RSA_PUBLIC_EXPONENT, exponent, &exp_len);
    TEE_CloseObject(pubkey_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get exponent: 0x%08x", res);
        return res;
    }

    /* Copy modulus and exponent into output buffer */
    TEE_MemMove(public_key, modulus, mod_len);
    TEE_MemMove(public_key + mod_len, exponent, exp_len);
    *public_key_len = mod_len + exp_len;

    DMSG("RSA public key successfully retrieved");
    return TEE_SUCCESS;
}

/**
 * Encrypt data using AES-CTR mode
 *
 * This function encrypts the provided plaintext data using AES in CTR mode.
 * It retrieves the AES key from secure storage, generates a random IV, and performs the encryption.
 * The IV is prepended to the ciphertext (on the first AES_BLOCK_SIZE bytes).
 * The ciphertext buffer must be large enough to hold the IV and the encrypted data.
 * The ciphertext buffer will contain the following structure: [IV][Encrypted Data].
 *
 * @param plaintext Pointer to the data to be encrypted
 * @param plaintext_len Length of the plaintext data
 * @param ciphertext Pointer to the buffer where the encrypted data will be stored
 * @param ciphertext_len Length of the ciphertext buffer, will be updated with actual size
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result encrypt_aes_data(const char *plaintext, size_t plaintext_len, char *ciphertext, size_t *ciphertext_len)
{
    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    char iv[AES_BLOCK_SIZE] = {0};
    uint32_t enc_len = 0;

    /* Retrieve the AES key from persistent storage or generate a new one */
    res = generate_aes_key(&key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to retrieve AES key, res=0x%08x", res);
        goto exit;
    }

    /* Allocate AES-CTR operation */
    res = TEE_AllocateOperation(&operation, TEE_ALG_AES_CTR, TEE_MODE_ENCRYPT, AES_KEY_SIZE);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate operation, res=0x%08x", res);
        goto exit;
    }

    res = TEE_SetOperationKey(operation, key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to set operation key, res=0x%08x", res);
        goto exit;
    }

    /* Generate a new random IV */
    TEE_GenerateRandom(iv, AES_BLOCK_SIZE);
    memcpy(ciphertext, iv, AES_BLOCK_SIZE);

    TEE_CipherInit(operation, iv, AES_BLOCK_SIZE);

    /* Encrypt plaintext after the IV in ciphertext buffer */
    enc_len = (uint32_t)(*ciphertext_len - AES_BLOCK_SIZE);
    res = TEE_CipherUpdate(operation, plaintext, plaintext_len, ciphertext + AES_BLOCK_SIZE, &enc_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to encrypt data, res=0x%08x", res);
        goto exit;
    }

    *ciphertext_len = AES_BLOCK_SIZE + enc_len;

exit:
    if (operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(operation);
    if (key_handle != TEE_HANDLE_NULL)
        TEE_CloseObject(key_handle);
    TEE_MemFill(iv, 0, sizeof(iv));

    return res;
}

/**
 * Decrypt data using AES-CTR mode
 *
 * This function decrypts the provided ciphertext data using AES in CTR mode.
 * It retrieves the AES key from secure storage, extracts the IV from the ciphertext, and performs the decryption.
 * The ciphertext must contain the IV in the first AES_BLOCK_SIZE bytes.
 * The plaintext buffer must be large enough to hold the decrypted data.
 * The plaintext buffer will be updated with the decrypted data size.
 * The ciphertext structure is expected to be: [IV][Encrypted Data].
 *
 * @param ciphertext Pointer to the data to be decrypted
 * @param ciphertext_len Length of the ciphertext data
 * @param plaintext Pointer to the buffer where the decrypted data will be stored
 * @param plaintext_len Length of the plaintext buffer, will be updated with actual size
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result decrypt_aes_data(const char *ciphertext, size_t ciphertext_len, char *plaintext, size_t *plaintext_len)
{
    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    char iv[AES_BLOCK_SIZE] = {0};
    uint32_t dec_len = 0;

    /* Check if the output buffer is large enough */
    if (ciphertext_len < AES_BLOCK_SIZE)
    {
        EMSG("Output buffer is too small, expected size: %u bytes", AES_BLOCK_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Extract IV from the start of ciphertext */
    memcpy(iv, ciphertext, AES_BLOCK_SIZE);

    /* Retrieve the AES key from persistent storage */
    res = generate_aes_key(&key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to retrieve AES key, res=0x%08x", res);
        goto exit;
    }

    /* Allocate decrypt operation */
    res = TEE_AllocateOperation(&operation, TEE_ALG_AES_CTR, TEE_MODE_DECRYPT, AES_KEY_SIZE);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate operation, res=0x%08x", res);
        goto exit;
    }

    res = TEE_SetOperationKey(operation, key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to set operation key, res=0x%08x", res);
        goto exit;
    }

    /* Initialize cipher with IV */
    TEE_CipherInit(operation, iv, AES_BLOCK_SIZE);

    /* Decrypt ciphertext (excluding the IV) */
    dec_len = (uint32_t)(*plaintext_len);
    size_t input_len = ciphertext_len - AES_BLOCK_SIZE;

    res = TEE_CipherUpdate(operation, ciphertext + AES_BLOCK_SIZE, input_len, plaintext, &dec_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to decrypt data, res=0x%08x", res);
        goto exit;
    }

    *plaintext_len = dec_len;

exit:
    if (operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(operation);
    if (key_handle != TEE_HANDLE_NULL)
        TEE_CloseObject(key_handle);
    TEE_MemFill(iv, 0, sizeof(iv));

    return res;
}
