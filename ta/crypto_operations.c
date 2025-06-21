#include <crypto_operations.h>

#define RSA_STORAGE_NAME "rsaKeyPair"
#define RSA_KEY_SIZE 2048

#define AES_KEY_STORAGE_NAME "aesKey"
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 256

/**
 * Compute SHA256 hash of the JSON data
 * @param json_data: pointer to the JSON data
 * @param json_data_sz: size of the JSON data
 * @param hash_output: pointer to the output buffer for the hash
 * @param hash_output_sz: size of the output buffer, will be updated with actual size
 */
static TEE_Result compute_sha256(char *json_data, size_t json_data_sz, char *hash_output, size_t *hash_output_sz)
{
    TEE_ObjectHandle object;
    TEE_Result res;

    /* Check if the output buffer is large enough */
    if (*hash_output_sz < TEE_SHA256_HASH_SIZE)
    {
        EMSG("Output buffer is too small, expected size: %zu", TEE_SHA256_HASH_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Allocate transient object for SHA256 */
    res = TEE_AllocateTransientObject(TEE_TYPE_SHA256, sizeof(TEE_ObjectHandle), &object);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate transient object, res=0x%08x", res);
        return res;
    }

    /* Initialize the hash object */
    res = TEE_InitRefHash(object, TEE_ALG_SHA256);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to initialize hash object, res=0x%08x", res);
        TEE_Free(object);
        return res;
    }

    /* Update the hash with JSON data */
    res = TEE_DigestUpdate(object, json_data, json_data_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to update hash, res=0x%08x", res);
        TEE_Free(object);
        return res;
    }

    /* Finalize the hash and get the output */
    res = TEE_DigestDoFinal(object, NULL, 0, hash_output, hash_output_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to finalize hash, res=0x%08x", res);
        TEE_Free(object);
        return res;
    }

    TEE_Free(object);
    return TEE_SUCCESS;
}

/**
 * Generate public and private key and store them separately in secure storage
 * @param key_pair_handle pointer to the handle of the RSA key pair object
 */
static TEE_Result generate_rsa_key_pair(TEE_ObjectHandle *key_pair_handle)
{
    TEE_Result res;
    TEE_Attribute attrs[1];
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ; /* we need read and write access */

    /* Check if the key pair already exists in secure storage */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,      /* storageID */
        RSA_STORAGE_NAME,         /* objectID */
        sizeof(RSA_STORAGE_NAME), /* objectIDLen */
        flags,                    /* flags */
        key_pair_handle           /* object */
    );

    if (res == TEE_SUCCESS)
    {
        DMSG("RSA key pair retrieved from persistent storage");
        return TEE_SUCCESS; /* Key pair already exists */
    }

    if (res != TEE_ERROR_ITEM_NOT_FOUND)
    {
        EMSG("Failed to open RSA key pair object: 0x%08x", res);
        return res; /* Error opening the key pair */
    }

    /* Key pair does not exist, generate a new one */
    DMSG("Generating new RSA key pair");

    TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, RSA_KEY_SIZE, &transient_key);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate transient object for key pair, res=0x%08x", res);
        return res;
    }

    /* Set key generation attributes */
    TEE_InitValueAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS_SIZE, RSA_KEY_SIZE, 0);

    res = TEE_GenerateKey(transient_key, RSA_KEY_SIZE, attrs, 1);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to generate RSA key pair, res=0x%08x", res);
        return res;
    }

    flags |= TEE_DATA_FLAG_ACCESS_WRITE; /* we also need write access */
    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,      /* storageID */
        RSA_STORAGE_NAME,         /* objectID */
        sizeof(RSA_STORAGE_NAME), /* objectIDLen */
        flags,                    /* flags */
        transient_key,            /* attributes */
        NULL, 0,                  /* initialData , initialDataLen */
        key_pair_handle           /* object */
    );

    TEE_FreeTransientObject(transient_key);

    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to store RSA key pair, res=0x%08x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    DMSG("RSA key pair successfully generated and stored");
    return TEE_SUCCESS;
}

/** Generate a new AES key and store it in secure storage */
static TEE_Result generate_aes_key(TEE_ObjectHandle *key_handle)
{
    TEE_Result res;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ; /* we only need read access */

    /* Verify if the AES key already exists in secure storage */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,          /* storageID */
        AES_KEY_STORAGE_NAME,         /* objectID */
        sizeof(AES_KEY_STORAGE_NAME), /* objectIDLen */
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

    TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;

    /* Allocate a transient object for AES */
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, sizeof(TEE_ObjectHandle), &transient_key);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate transient object for AES, res=0x%08x", res);
        return res;
    }

    /* Generate a random AES key */
    res = TEE_GenerateKey(*key_handle, AES_KEY_SIZE, NULL, 0);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to generate AES key, res=0x%08x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    /* Store the AES key in secure storage */
    TEE_ObjectHandle persistent_key;
    flags |= TEE_DATA_FLAG_ACCESS_WRITE; /* we also need write access */
    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,          /* storageID */
        AES_KEY_STORAGE_NAME,         /* objectID */
        sizeof(AES_KEY_STORAGE_NAME), /* objectIDLen */
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
 * Encrypt data using AES-CTR mode
 * @param plaintext: pointer to the data to be encrypted
 * @param plaintext_len: length of the plaintext data
 * @param ciphertext: pointer to the buffer where the encrypted data will be stored
 * @param ciphertext_len: length of the ciphertext buffer, will be updated with actual size
 */
static TEE_Result encrypt_aes_data(const char *plaintext, size_t plaintext_len, char *ciphertext, size_t *ciphertext_len)
{
    TEE_Result res;
    char iv[AES_BLOCK_SIZE];
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    uint32_t read_bytes = 0;

    /* Ensure output buffer can hold IV + ciphertext */
    if (*ciphertext_len < plaintext_len + AES_BLOCK_SIZE)
    {
        EMSG("Output buffer is too small, expected size: %zu", plaintext_len + AES_BLOCK_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Retrieve the AES key from persistent storage or generate a new one */
    res = generate_aes_key(&key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to generate AES key, res=0x%08x", res);
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

    /* Generate a new random IV for each encryption */
    res = TEE_GenerateRandom(iv, AES_BLOCK_SIZE);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to generate random IV, res=0x%08x", res);
        goto exit;
    }

    /* Copy IV to start of ciphertext */
    memcpy(ciphertext, iv, AES_BLOCK_SIZE);

    res = TEE_CipherInit(operation, iv, AES_BLOCK_SIZE);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to initialize cipher operation, res=0x%08x", res);
        goto exit;
    }

    /* Encrypt plaintext after the IV in ciphertext buffer */
    uint32_t enc_len = *ciphertext_len - AES_BLOCK_SIZE;
    res = TEE_CipherUpdate(operation, plaintext, plaintext_len, ciphertext + AES_BLOCK_SIZE, &enc_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to encrypt data, res=0x%08x", res);
        goto exit;
    }

    res = TEE_CipherDoFinal(operation, NULL, 0, ciphertext + AES_BLOCK_SIZE + enc_len, &read_bytes);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to finalize encryption, res=0x%08x", res);
        goto exit;
    }

    *ciphertext_len = AES_BLOCK_SIZE + enc_len + read_bytes;

exit:
    if (operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(operation);
    if (key_handle != TEE_HANDLE_NULL)
        TEE_CloseObject(key_handle);

    return res;
}

/**
 * Decrypt data using AES-CTR mode
 * @param ciphertext: pointer to the data to be decrypted
 * @param ciphertext_len: length of the ciphertext data
 * @param plaintext: pointer to the buffer where the decrypted data will be stored
 * @param plaintext_len: length of the plaintext buffer, will be updated with actual size
 */
static TEE_Result decrypt_aes_data(const char *ciphertext, size_t ciphertext_len, char *plaintext, size_t *plaintext_len)
{
    TEE_Result res;
    char iv[AES_BLOCK_SIZE];
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    uint32_t read_bytes = 0;

    /* Check if the output buffer is large enough */
    if (ciphertext_len < AES_BLOCK_SIZE)
    {
        EMSG("Output buffer is too small, expected size: %zu", ciphertext_len);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Check if output buffer is large enough */
    if (*plaintext_len < ciphertext_len - AES_BLOCK_SIZE)
    {
        EMSG("Output buffer is too small, expected size: %zu", ciphertext_len - AES_BLOCK_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Extract IV from the start of ciphertext */
    const char *iv = ciphertext;
    const char *enc_data = ciphertext + AES_BLOCK_SIZE;
    size_t enc_data_len = ciphertext_len - AES_BLOCK_SIZE;

    /* Retrieve the AES key from persistent storage */
    res = generate_aes_key(&key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to generate AES key, res=0x%08x", res);
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
    res = TEE_CipherInit(operation, iv, AES_BLOCK_SIZE);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to initialize cipher operation, res=0x%08x", res);
        goto exit;
    }

    uint32_t out_len = (uint32_t)*plaintext_len;
    res = TEE_CipherUpdate(operation, enc_data, enc_data_len, plaintext, &out_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to decrypt data, res=0x%08x", res);
        goto exit;
    }

    res = TEE_CipherDoFinal(operation, NULL, 0, plaintext + out_len, &read_bytes);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to finalize decryption, res=0x%08x", res);
        goto exit;
    }

    *plaintext_len = out_len + read_bytes;

exit:
    if (operation != TEE_HANDLE_NULL)
        TEE_FreeOperation(operation);
    if (key_handle != TEE_HANDLE_NULL)
        TEE_CloseObject(key_handle);

    return res;
}
