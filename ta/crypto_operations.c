#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <crypto_operations_ta.h>
#include <secure_storage_ta.h>

/**
 * Compute SHA256 hash of the data
 * @param data Pointer to the data to be hashed
 * @param data_sz Size of the data
 * @param hash_output Pointer to the output buffer for the hash
 * @param hash_output_sz Size of the output buffer, will be updated with actual size
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
 * Generate RSA key pair and store it in secure storage
 * @param key_pair_handle Pointer to the handle of the RSA key pair object
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
        transient_key,                    /* object */
        NULL, 0,                          /* initialData , initialDataLen */
        key_pair_handle                   /* object handle */
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
 * @param key_handle Pointer to the handle of the AES key object
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
 * Sign the TA UUID for attestation
 * @param signature Buffer to store the signature output
 * @param sig_len Pointer to size of signature buffer
 */
TEE_Result get_code_attestation(void *signature, size_t *sig_len)
{
    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle sign_op = TEE_HANDLE_NULL;
    TEE_UUID uuid = TA_OFF_CHAIN_SECURE_STORAGE_UUID;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ;

    char hash[SHA256_HASH_SIZE];
    size_t hash_len = sizeof(hash);

    /* Check if the signature buffer is large enough */
    if (*sig_len < RSA_SIGNATURE_SIZE)
    {
        EMSG("Signature buffer too small, expected size: %u bytes", RSA_SIGNATURE_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Compute SHA256 hash of the UUID */
    res = compute_sha256((char *)&uuid, sizeof(uuid), hash, &hash_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to compute SHA256 of UUID: 0x%08x", res);
        return res;
    }

    /* Open the persistent RSA key pair */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,              /* storageID */
        RSA_KEYPAIR_STORAGE_NAME,         /* objectID */
        strlen(RSA_KEYPAIR_STORAGE_NAME), /* objectIDLen */
        flags,                            /* flags */
        &key_handle                       /* object */
    );
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to open RSA key pair for signing, res=0x%08x", res);
        return res;
    }

    /* Prepare operation handle for signing:
     *  - TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 - RSA PKCS#1 v1.5 with SHA-256
     *  - TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 - RSA PSS with MGF1 and SHA-256 (has random salt)
     */
    res = TEE_AllocateOperation(
        &sign_op,                             /* operation */
        TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256, /* algorithm */
        TEE_MODE_SIGN,                        /* mode */
        RSA_KEY_SIZE_BITS                     /* maxKeySize */
    );
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate signing operation, res=0x%08x", res);
        TEE_CloseObject(key_handle);
        return res;
    }

    /* Set the key for the operation */
    res = TEE_SetOperationKey(sign_op, key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to set key for signing operation, res=0x%08x", res);
        TEE_FreeOperation(sign_op);
        TEE_CloseObject(key_handle);
        return res;
    }

    /* Sign the UUID */
    res = TEE_AsymmetricSignDigest(
        sign_op,            /* operation */
        NULL, 0,            /* params, paramsCount */
        hash,               /* digest */
        hash_len,           /* digestLen */
        signature,          /* signature */
        (uint32_t *)sig_len /* signatureLen */
    );

    TEE_FreeOperation(sign_op);
    TEE_CloseObject(key_handle);

    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to sign UUID, res=0x%08x", res);
    }

    DMSG("UUID successfully signed with RSA");
    return res;
}

/**
 * Retrieve the public key of the RSA key pair stored in secure storage
 * @param public_key Buffer to store the public key
 * @param public_key_len Pointer to size of public key buffer; updated with actual public key length
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
 * @param plaintext Pointer to the data to be encrypted
 * @param plaintext_len Length of the plaintext data
 * @param ciphertext Pointer to the buffer where the encrypted data will be stored
 * @param ciphertext_len Length of the ciphertext buffer, will be updated with actual size
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
 * @param ciphertext Pointer to the data to be decrypted
 * @param ciphertext_len Length of the ciphertext data
 * @param plaintext Pointer to the buffer where the decrypted data will be stored
 * @param plaintext_len Length of the plaintext buffer, will be updated with actual size
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
