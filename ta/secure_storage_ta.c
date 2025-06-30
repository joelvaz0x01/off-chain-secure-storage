/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <secure_storage_ta.h>
#include <crypto_operations_ta.h>

/**
 * Convert SHA256 hash to a hexadecimal string (no null-terminator)
 *
 * This function converts the SHA256 hash data into a hexadecimal string representation.
 * Each byte of the hash is represented by two hexadecimal characters.
 * The output buffer must be large enough to hold the hexadecimal string (64 characters for SHA256).
 *
 * @param output_hash_str Buffer to store the hexadecimal string representation of the hash
 * @param output_hash_str_sz Size of the output buffer
 * @param output_hash Pointer to the SHA256 hash data
 * @param output_hash_sz Size of the SHA256 hash data
 */
static TEE_Result hash_to_hex_str(char *output_hash_str, size_t output_hash_str_sz, char *hash, size_t hash_sz)
{
    // Make sure output buffer size is enough: 2 chars per byte
    if (output_hash_str_sz != SHA256_HASH_SIZE * 2)
    {
        EMSG("Output buffer size is incorrect, expected: %u, got: %zu", SHA256_HASH_SIZE * 2, output_hash_str_sz);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    for (size_t i = 0; i < hash_sz; i++)
    {
        snprintf(&output_hash_str[i * 2], 3, "%02x", (unsigned char)hash[i]);
    }
    return TEE_SUCCESS;
}

/**
 * Store JSON object in off-chain secure storage (persistent object)
 *
 * This function stores JSON data associated with an IoT device ID in secure storage.
 * It performs the following steps:
 *   1. Takes the IoT device ID and JSON data as input parameters;
 *   2. Computes the SHA256 hash of the JSON data;
 *   3. Converts the hash to a hexadecimal string representation;
 *   4. Uses this hash as the object ID for the persistent object;
 *   5. Encrypts the JSON data using AES before storing it in the persistent object.
 *   6. Returns the hash of original JSON data in the output parameter.
 *
 * @param param_types Expected parameter types
 * @param params Parameters passed to the TA
 * @return TEE_Success on success, or another code if an error occurs
 */
static TEE_Result store_json_data(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE);

    TEE_ObjectHandle object;
    TEE_Result res;
    char *iot_device_id;      /* param[0].buffer */
    size_t iot_device_id_sz;  /* param[0].size */
    char *data = NULL;        /* param[1].buffer */
    size_t data_sz;           /* param[1].size */
    char *output_hash = NULL; /* param[2].buffer */
    size_t output_hash_sz;    /* param[2].size */

    size_t aux_hash_sz = SHA256_HASH_SIZE * 2; /* Size for the hexadecimal string representation of the hash */
    char aux_hash[SHA256_HASH_SIZE * 2];       /* Auxiliary buffer for the hash in hex format */

    size_t final_data_sz = 0; /* Size of the final encrypted data */
    char *final_data = NULL;  /* Final buffer for encrypted data */

    uint32_t flag = TEE_DATA_FLAG_ACCESS_READ; /* we can read the object */

    /* Safely get the invocation parameters */
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Allocate memory for IoT Device ID */
    iot_device_id_sz = params[0].memref.size;
    iot_device_id = TEE_Malloc(iot_device_id_sz, 0);
    if (!iot_device_id)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }
    TEE_MemMove(iot_device_id, params[0].memref.buffer, iot_device_id_sz);

    /* Allocate memory for JSON data */
    data_sz = params[1].memref.size;
    data = TEE_Malloc(data_sz, 0);
    if (!data)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }
    TEE_MemMove(data, params[1].memref.buffer, data_sz);

    /* Allocate memory for the output hash */
    output_hash_sz = params[2].memref.size;
    output_hash = TEE_Malloc(output_hash_sz, 0);
    if (!output_hash)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    /* Allocate memory for the final encrypted data */
    final_data_sz = data_sz + AES_BLOCK_SIZE;
    final_data = TEE_Malloc(final_data_sz, 0);
    if (!final_data)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    /* Compute SHA256 hash of the data */
    res = compute_sha256(data, data_sz, output_hash, &output_hash_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to compute SHA256 hash, res=0x%08x", res);
        goto exit;
    }

    /* Convert the hash to a hexadecimal string */
    res = hash_to_hex_str(aux_hash, aux_hash_sz, output_hash, output_hash_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to convert hash to hex string, res=0x%08x", res);
        goto exit;
    }

    /* Check if the output buffer is large enough and copy the hash */
    if (aux_hash_sz <= params[2].memref.size)
        TEE_MemMove(params[2].memref.buffer, aux_hash, aux_hash_sz);
    else
    {
        res = TEE_ERROR_SHORT_BUFFER;
        goto exit;
    }

    /* Encrypt data */
    res = encrypt_aes_data(data, data_sz, final_data, &final_data_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to encrypt data, res=0x%08x", res);
        goto exit;
    }

    /* Create object in secure storage and fill with data */
    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE, /* storageID */
        aux_hash,            /* objectID */
        aux_hash_sz,         /* objectIDLen */
        flag,                /* flags */
        TEE_HANDLE_NULL,     /* attributes */
        final_data,          /* initialData */
        final_data_sz,       /* initialDataLen */
        &object              /* object */
    );
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
        goto exit;
    }

exit:
    if (object != TEE_HANDLE_NULL)
        TEE_CloseObject(object);

    if (data)
    {
        TEE_MemFill(data, 0, data_sz);
        TEE_Free(data);
    }
    if (output_hash)
    {
        TEE_MemFill(output_hash, 0, output_hash_sz);
        TEE_Free(output_hash);
    }
    if (iot_device_id)
        TEE_Free(iot_device_id);

    return res;
}

/**
 * Retrieve JSON object from off-chain secure storage (persistent object)
 *
 * This function retrieves JSON data associated with an IoT device ID from secure storage.
 * It performs the following steps:
 *   1. Takes the hash of data as input parameter;
 *   2. Uses the hash as the object ID to open the persistent object;
 *   3. Reads the encrypted data from the persistent object;
 *   4. Decrypts the data using AES;
 *   5. Returns it in the output.
 *
 * @param param_types Expected parameter types of the command
 * @param params Parameters of the command
 * @return TEE_Success on success, or another code if an error occurs
 */
static TEE_Result retrieve_json_data(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    TEE_ObjectHandle object = TEE_HANDLE_NULL;
    TEE_ObjectInfo object_info;
    TEE_Result res;

    char *hash_input;            /* param[0].buffer */
    size_t hash_input_sz;        /* param[0].size */
    char *decrypted_data = NULL; /* param[1].buffer */
    size_t decrypted_data_sz;    /* param[1].size */

    char *encrypted_data = NULL;  /* Auxiliary buffer for encrypted data */
    size_t encrypted_data_sz = 0; /* Auxiliary size for encrypted data */

    uint32_t flag = TEE_DATA_FLAG_ACCESS_READ; /* we can read the object */
    uint32_t read_bytes = 0;

    /* Safely get the invocation parameters */
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Allocate buffer for hash input */
    hash_input_sz = params[0].memref.size;
    hash_input = TEE_Malloc(hash_input_sz, 0);
    if (!hash_input)
        return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(hash_input, params[0].memref.buffer, hash_input_sz);

    decrypted_data_sz = params[1].memref.size;

    /* Check if the object exist and open it for reading */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE, /* storageID */
        hash_input,          /* objectID */
        hash_input_sz,       /* objectIDLen */
        flag,                /* flags */
        &object              /* object */
    );
    if (res == TEE_ERROR_ITEM_NOT_FOUND)
    {
        EMSG("Persistent object not found for hash: %s", hash_input);
        goto exit;
    }
    else if (res != TEE_SUCCESS)
    {
        EMSG("Failed to open persistent object, res=0x%08x", res);
        goto exit;
    }

    /* Get info about the object */
    res = TEE_GetObjectInfo1(object, &object_info);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get object info, res=0x%08x", res);
        goto exit;
    }
    encrypted_data_sz = object_info.dataSize;

    /* Allocate buffer for encrypted data */
    encrypted_data = TEE_Malloc(encrypted_data_sz, 0);
    if (!encrypted_data)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    /* Read encrypted data */
    res = TEE_ReadObjectData(object, encrypted_data, encrypted_data_sz, &read_bytes);
    if (res != TEE_SUCCESS || read_bytes != encrypted_data_sz)
    {
        EMSG("TEE_ReadObjectData failed 0x%08x, read %u over %lu", res, read_bytes, encrypted_data_sz);
        goto exit;
    }

    /* Allocate buffer for decrypted data */
    decrypted_data = TEE_Malloc(decrypted_data_sz, 0);
    if (!decrypted_data)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    /* Decrypt the data */
    res = decrypt_aes_data(encrypted_data, encrypted_data_sz, decrypted_data, &decrypted_data_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to decrypt data, res=0x%08x", res);
        goto exit;
    }

    /* Copy decrypted data to output buffer */
    TEE_MemMove(params[1].memref.buffer, decrypted_data, decrypted_data_sz);
    params[1].memref.size = decrypted_data_sz;

exit:
    if (object != TEE_HANDLE_NULL)
        TEE_CloseObject(object);
    if (hash_input)
        TEE_Free(hash_input);
    if (encrypted_data)
    {
        TEE_MemFill(encrypted_data, 0, encrypted_data_sz);
        TEE_Free(encrypted_data);
    }
    if (decrypted_data)
    {
        TEE_MemFill(decrypted_data, 0, decrypted_data_sz);
        TEE_Free(decrypted_data);
    }
    return res;
}

/**
 * Hash a given JSON object using SHA256
 *
 * This function computes the SHA256 hash of the provided JSON data.
 *   1. Takes the JSON data as input;
 *   2. Computes its hash;
 *   3. Converts the hash to a hexadecimal string representation;
 *   4. Returns it in the output parameter.
 * The output buffer must be large enough to hold the hexadecimal string (64 characters for SHA256).
 *
 * @param param_types Expected parameter types
 * @param params Parameters passed to the TA
 * @return TEE_Success on success, or another code if an error occurs
 */
static TEE_Result hash_json_data(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    TEE_Result res;
    char *data;            /* param[0].buffer */
    size_t data_sz;        /* param[0].size */
    char *hash_output;     /* param[1].buffer */
    size_t hash_output_sz; /* param[1].size */

    size_t aux_hash_sz = SHA256_HASH_SIZE; /* Size of auxiliary hash buffer */
    char aux_hash[aux_hash_sz];            /* Auxiliary buffer for SHA256 hash */

    /* Safely get the invocation parameters */
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Allocate buffer for JSON data */
    data_sz = params[0].memref.size;
    data = TEE_Malloc(data_sz, 0);
    if (!data)
        return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(data, params[0].memref.buffer, data_sz);

    /* Allocate buffer for the hash output */
    hash_output_sz = params[1].memref.size;
    hash_output = TEE_Malloc(hash_output_sz, 0);
    if (!hash_output)
    {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    /* Compute SHA256 hash of the JSON data */
    res = compute_sha256(data, data_sz, aux_hash, &aux_hash_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to compute SHA256 hash, res=0x%08x", res);
        goto exit;
    }

    /* Convert the hash output to a hexadecimal string representation */
    res = hash_to_hex_str(hash_output, hash_output_sz, aux_hash, aux_hash_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to convert hash output to hex string, res=0x%08x", res);
        goto exit;
    }

    /* Copy the hash output to the output parameter */
    TEE_MemMove(params[1].memref.buffer, hash_output, hash_output_sz);
    params[1].memref.size = hash_output_sz;

exit:
    if (data)
    {
        TEE_MemFill(data, 0, data_sz);
        TEE_Free(data);
    }
    if (hash_output)
    {
        TEE_MemFill(hash_output, 0, hash_output_sz);
        TEE_Free(hash_output);
    }

    return res;
}

/**
 * Get attestation data of the TA
 * @param param_types Expected parameter types
 * @param params Parameters passed to the TA
 * @return TEE_Success on success, or another code if an error occurs
 */
static TEE_Result get_attestation(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    TEE_Result res;
    size_t attestation_data_sz;
    void *attestation_data;

    /* Safely get the invocation parameters */
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Allocate buffer for attestation data */
    attestation_data_sz = params[0].memref.size;
    attestation_data = TEE_Malloc(attestation_data_sz, 0);
    if (!attestation_data)
        return TEE_ERROR_OUT_OF_MEMORY;

    /* Get code attestation data */
    res = get_code_attestation(attestation_data, &attestation_data_sz);
    if (res == TEE_ERROR_SHORT_BUFFER)
    {
        EMSG("The provided buffer is too small, expected size: %zu bytes", attestation_data_sz);
        goto exit;
    }
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get code attestation data, res=0x%08x", res);
        goto exit;
    }

    /* Copy the attestation data to the output parameter */
    TEE_MemMove(params[0].memref.buffer, attestation_data, attestation_data_sz);
    params[0].memref.size = attestation_data_sz;

exit:
    if (attestation_data)
    {
        TEE_MemFill(attestation_data, 0, attestation_data_sz);
        TEE_Free(attestation_data);
    }
    return res;
}

/**
 * Get the public key of the RSA key pair stored in secure storage
 *
 * This function retrieves the public key of the RSA key pair used for signing attestation reports.
 * It performs the following steps:
 *   1. Allocates memory for the public key;
 *   2. Calls the function that retrieves the RSA public key from secure storage;
 *   3. Copies the public key to the output parameter.
 * The output buffer must be large enough to hold the public key.
 *
 * @param param_types Expected parameter types
 * @param params Parameters passed to the TA
 * @return TEE_Success on success, or another code if an error occurs
 */
static TEE_Result get_public_key(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    TEE_Result res;
    size_t public_key_sz;
    void *public_key;

    /* Safely get the invocation parameters */
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    public_key_sz = params[0].memref.size;
    public_key = TEE_Malloc(public_key_sz, 0);
    if (!public_key)
    {
        EMSG("Failed to allocate memory for public key");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* Get the public key */
    res = get_rsa_public_key(public_key, &public_key_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get public key, res=0x%08x", res);
        goto exit;
    }

    /* Copy the public key to the output parameter */
    TEE_MemMove(params[0].memref.buffer, public_key, public_key_sz);
    params[0].memref.size = public_key_sz;

exit:
    if (public_key)
    {
        TEE_MemFill(public_key, 0, public_key_sz);
        TEE_Free(public_key);
    }

    return res;
}

/**
 * Create entry point for the TA
 *
 * This function is called when the TA is loaded into memory.
 *
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result res;
    TEE_ObjectHandle rsa_key = TEE_HANDLE_NULL;
    TEE_ObjectHandle aes_key = TEE_HANDLE_NULL;

    /* Generate RSA key pair */
    res = generate_rsa_key_pair(&rsa_key);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to generate RSA key pair: 0x%08x", res);
        return res;
    }

    /* Generate AES key */
    res = generate_aes_key(&aes_key);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to generate AES key: 0x%08x", res);
        /* Clean up RSA key handle before returning */
        if (rsa_key != TEE_HANDLE_NULL)
            TEE_CloseObject(rsa_key);
        return res;
    }

    /* Close handles if they are no longer needed here */
    if (rsa_key != TEE_HANDLE_NULL)
        TEE_CloseObject(rsa_key);
    if (aes_key != TEE_HANDLE_NULL)
        TEE_CloseObject(aes_key);

    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    /* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types, TEE_Param __unused params[4], void __unused **session)
{
    /* Nothing to do */
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
    /* Nothing to do */
}

/**
 * Invoke a command in the TA
 *
 * This function is called when a command is invoked on the TA.
 *
 * @param session Session context
 * @param command Command ID
 * @param param_types Parameter types
 * @param params Parameters passed to the TA
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result TA_InvokeCommandEntryPoint(void __unused *session, uint32_t command, uint32_t param_types, TEE_Param params[4])
{
    if (TA_OFF_CHAIN_SECURE_STORAGE_STORE_JSON == command)
    {
        return store_json_data(param_types, params);
    }
    else if (TA_OFF_CHAIN_SECURE_STORAGE_RETRIEVE_JSON == command)
    {
        return retrieve_json_data(param_types, params);
    }
    else if (TA_OFF_CHAIN_SECURE_STORAGE_HASH_JSON == command)
    {
        return hash_json_data(param_types, params);
    }
    else if (TA_OFF_CHAIN_SECURE_STORAGE_GET_ATTESTATION == command)
    {
        return get_attestation(param_types, params);
    }
    else if (TA_OFF_CHAIN_SECURE_STORAGE_GET_PUBLIC_KEY == command)
    {
        return get_public_key(param_types, params);
    }
    else
    {
        EMSG("Command ID 0x%x is not supported", command);
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
