#include <crypto_operations.h>
#include <secure_storage_ta.h>
#include <string.h>

#define ED25519_STORAGE_NAME "ed25519KeyPair"
#define ED25519_PUBLIC_KEY_NAME "ed25519PublicKey"
#define ED25519_SIGNATURE_SIZE 64
#define ED25519_PUBLIC_KEY_SIZE 32

#define AES_KEY_STORAGE_NAME "aesKey"
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 256

/**
 * Compute SHA256 hash of the data
 * @param data Pointer to the data to be hashed
 * @param data_sz Size of the data
 * @param hash_output Pointer to the output buffer for the hash
 * @param hash_output_sz Size of the output buffer, will be updated with actual size
 */
static TEE_Result compute_sha256(char *data, size_t data_sz, char *hash_output, size_t *hash_output_sz)
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;

    /* Check if the output buffer is large enough */
    if (*hash_output_sz < TEE_SHA256_HASH_SIZE)
    {
        EMSG("Output buffer is too small, expected size: %zu bytes", TEE_SHA256_HASH_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Allocate transient object for SHA256 */
    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate operation, res=0x%08x", res);
        return res;
    }

    /* Initialize the digest operation */
    res = TEE_DigestUpdate(op, data, data_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to update digest, res=0x%08x", res);
        goto exit;
    }

    /* Finalize the digest and get the output */
    res = TEE_DigestDoFinal(op, NULL, 0, hash_output, hash_output_sz);
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
 * Generate Ed25519 public and private key and store it in secure storage
 * @param key_pair_handle Pointer to the handle of the Ed25519 key pair object
 */
static TEE_Result generate_ed25519_key_pair(TEE_ObjectHandle *key_pair_handle)
{
    TEE_Result res;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ; /* we need read and write access */
    TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;
    TEE_ObjectHandle pubkey_object = TEE_HANDLE_NULL;
    char public_key[ED25519_PUBLIC_KEY_SIZE];

    /* Check if the key pair already exists in secure storage */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,          /* storageID */
        ED25519_STORAGE_NAME,         /* objectID */
        strlen(ED25519_STORAGE_NAME), /* objectIDLen */
        flags,                        /* flags */
        key_pair_handle               /* object */
    );

    if (res == TEE_SUCCESS)
    {
        DMSG("Ed25519 key pair retrieved from persistent storage");
        return TEE_SUCCESS; /* Key pair already exists */
    }

    if (res != TEE_ERROR_ITEM_NOT_FOUND)
    {
        EMSG("Failed to open Ed25519 key pair object: 0x%08x", res);
        return res; /* Error opening the key pair */
    }

    /* Key pair does not exist, generate a new one */
    DMSG("Generating new Ed25519 key pair");

    res = TEE_AllocateTransientObject(TEE_TYPE_ED25519_KEYPAIR, 0, &transient_key);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate transient object for key pair, res=0x%08x", res);
        return res;
    }

    /* Generate key pair */
    res = TEE_GenerateKey(transient_key, 0, NULL, 0);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to generate Ed25519 key pair, res=0x%08x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    /* Extract public key */
    res = TEE_GetObjectBufferAttribute(
        transient_key,                 /* object */
        TEE_ATTR_ED25519_PUBLIC_VALUE, /* attributeID */
        public_key,                    /* buffer */
        sizeof(public_key)             /* size */
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to extract Ed25519 public key: 0x%08x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    /* Store the key pair */
    flags |= TEE_DATA_FLAG_ACCESS_WRITE_META; /* we need write-meta access */
    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,          /* storageID */
        ED25519_STORAGE_NAME,         /* objectID */
        strlen(ED25519_STORAGE_NAME), /* objectIDLen */
        flags,                        /* flags */
        transient_key,                /* attributes */
        NULL, 0,                      /* initialData , initialDataLen */
        key_pair_handle               /* object */
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to store Ed25519 key pair, res=0x%08x", res);
        TEE_FreeTransientObject(transient_key);
        return res;
    }

    /* Store the public key in persistent storage */
    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,             /* storageID */
        ED25519_PUBLIC_KEY_NAME,         /* objectID */
        strlen(ED25519_PUBLIC_KEY_NAME), /* objectIDLen */
        flags,                           /* flags */
        TEE_HANDLE_NULL,                 /* attributes */
        public_key,                      /* initialData */
        sizeof(public_key),              /* initialDataLen */
        &pubkey_object                   /* object */
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to store Ed25519 public key, res=0x%08x", res);

        /* Clean up the key pair from persistent storage if public key storage fails */
        if (*key_pair_handle != TEE_HANDLE_NULL)
        {
            TEE_CloseAndDeletePersistentObject1(*key_pair_handle);
            *key_pair_handle = TEE_HANDLE_NULL;
        }

        TEE_FreeTransientObject(transient_key);
        return res;
    }

    TEE_CloseObject(pubkey_object);

    DMSG("Ed25519 key pair successfully generated and stored");
    return TEE_SUCCESS;
}

/**
 * Generate a new AES key and store it in secure storage
 * @param key_handle Pointer to the handle of the AES key object
 */
static TEE_Result generate_aes_key(TEE_ObjectHandle *key_handle)
{
    TEE_Result res;
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
static TEE_Result get_code_attestation(void *signature, size_t *sig_len)
{
    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ;

    /* Check if the signature buffer is large enough */
    if (*sig_len < ED25519_SIGNATURE_SIZE)
    {
        EMSG("Signature buffer too small, expected size: %zu bytes", ED25519_SIGNATURE_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Open the persistent Ed25519 key pair */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,
        ED25519_STORAGE_NAME,
        strlen(ED25519_STORAGE_NAME),
        flags,
        &key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to open Ed25519 key pair for signing, res=0x%08x", res);
        return res;
    }

    /* Prepare operation handle for signing */
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
    res = TEE_AllocateOperation(&op_handle, TEE_ALG_ED25519, TEE_MODE_SIGN, 0);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to allocate signing operation, res=0x%08x", res);
        TEE_CloseObject(key_handle);
        return res;
    }

    /* Set the key for the operation */
    res = TEE_SetOperationKey(op_handle, key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to set key for signing operation, res=0x%08x", res);
        TEE_FreeOperation(op_handle);
        TEE_CloseObject(key_handle);
        return res;
    }

    /* Sign the UUID */
    res = TEE_AsymmetricSignDigest(
        op_handle,                                 /* operation */
        NULL, 0,                                   /* params, paramsCount */
        (void *)&TA_OFF_CHAIN_SECURE_STORAGE_UUID, /* digest */
        sizeof(TEE_UUID),                          /* digestLen */
        signature,                                 /* signature */
        sig_len                                    /* signatureLen */
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to sign UUID, res=0x%08x", res);
    }
    TEE_FreeOperation(op_handle);
    TEE_CloseObject(key_handle);

    DMSG("UUID successfully signed with Ed25519");
    return res;
}

/**
 * Retrieve the public key of the Ed25519 key pair stored in secure storage
 * @param public_key Buffer to store the public key
 * @param public_key_len Pointer to size of public key buffer; updated with actual public key length
 */
static TEE_Result get_ed25519_public_key(char *public_key, size_t *public_key_len)
{
    TEE_Result res;
    TEE_ObjectHandle pubkey_handle = TEE_HANDLE_NULL;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ;
    uint32_t read_bytes = 0;

    /* Check if the public key buffer is large enough */
    if (*public_key_len < ED25519_PUBLIC_KEY_SIZE)
    {
        EMSG("Public key buffer too small, expected size: %zu bytes", ED25519_PUBLIC_KEY_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Open the persistent Ed25519 key pair */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,          /* storageID */
        ED25519_STORAGE_NAME,         /* objectID */
        strlen(ED25519_STORAGE_NAME), /* objectIDLen */
        flags,                        /* flags */
        &key_handle                   /* object */
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to open Ed25519 key pair for public key retrieval, res=0x%08x", res);
        return res;
    }

    /* Get the public key */
    res = TEE_ReadObjectData(pubkey_handle, public_key, ED25519_PUBLIC_KEY_SIZE, &read_bytes);
    TEE_CloseObject(pubkey_handle);

    if (res != TEE_SUCCESS || read_bytes != ED25519_PUBLIC_KEY_SIZE)
    {
        EMSG("Failed to read public key data, res=0x%08x, bytes read: %u", res, read_bytes);
        return res;
    }

    *public_key_len = read_bytes;

    DMSG("Ed25519 public key successfully retrieved");
    return TEE_SUCCESS;
}

/**
 * Encrypt data using AES-CTR mode
 * @param plaintext Pointer to the data to be encrypted
 * @param plaintext_len Length of the plaintext data
 * @param ciphertext Pointer to the buffer where the encrypted data will be stored
 * @param ciphertext_len Length of the ciphertext buffer, will be updated with actual size
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
        EMSG("Output buffer is too small, expected size: %zu bytes", plaintext_len + AES_BLOCK_SIZE);
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
 * @param ciphertext Pointer to the data to be decrypted
 * @param ciphertext_len Length of the ciphertext data
 * @param plaintext Pointer to the buffer where the decrypted data will be stored
 * @param plaintext_len Length of the plaintext buffer, will be updated with actual size
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
        EMSG("Output buffer is too small, expected size: %zu bytes", AES_BLOCK_SIZE);
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* Check if output buffer is large enough */
    if (*plaintext_len < ciphertext_len - AES_BLOCK_SIZE)
    {
        EMSG("Output buffer is too small, expected size: %zu bytes", ciphertext_len - AES_BLOCK_SIZE);
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
