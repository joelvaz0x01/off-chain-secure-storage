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
#include <secure_storage_ta.h>
#include <crypto_storage_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/**
 * Store JSON object in off-chain secure storage (persistent object)
 * @param param_types: expected parameter types
 * @param params: parameters passed to the TA
 */
static TEE_Result store_json_object(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    TEE_ObjectHandle object;
    TEE_Result res;
    char *iot_device_id;     /* param[0].buffer */
    size_t iot_device_id_sz; /* param[0].size */
    char *json_data;         /* param[1].buffer */
    size_t json_data_sz;     /* param[1].size */
    uint32_t data_flag;

    /* Safely get the invocation parameters */
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    iot_device_id_sz = params[0].memref.size;
    iot_device_id = TEE_Malloc(iot_device_id_sz, 0);
    if (!iot_device_id)
        return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(iot_device_id, params[0].memref.buffer, iot_device_id_sz);

    json_data_sz = params[1].memref.size;
    json_data = TEE_Malloc(json_data_sz, 0);
    if (!json_data)
        return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(json_data, params[1].memref.buffer, json_data_sz);

    /* Create object in secure storage and fill with data */
    data_flag =
        TEE_DATA_FLAG_ACCESS_READ |  /* we can later read the oject */
        TEE_DATA_FLAG_ACCESS_WRITE | /* we can later write into the object */
        TEE_DATA_FLAG_OVERWRITE;     /* destroy existing object of same IoT device ID */

    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,             /* storagID */
        iot_device_id, iot_device_id_sz, /* objectID, objectIDLen */
        data_flag,                       /* flags */
        TEE_HANDLE_NULL,                 /* attributes */
        json_data, json_data_sz,         /* initialData, initialDataLen */
        &object                          /* object */
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
        TEE_Free(iot_device_id);
        TEE_Free(json_data);
        return res;
    }

    res = TEE_WriteObjectData(object, json_data, json_data_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("TEE_WriteObjectData failed 0x%08x", res);
        TEE_CloseAndDeletePersistentObject1(object);
    }
    else
    {
        TEE_CloseObject(object);
    }
    TEE_Free(iot_device_id);
    TEE_Free(json_data);
    TEE_Free(data);
    return res;
}

/**
 * Retrieve JSON object from off-chain secure storage (persistent object)
 * @param param_types: parameter types of the command
 * @param params: parameters of the command
 */
static TEE_Result retrieve_json_object(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    TEE_ObjectHandle object;
    TEE_ObjectInfo object_info;
    TEE_Result res;
    uint32_t read_bytes;
    char *json_hash;     /* param[0].buffer */
    size_t json_hash_sz; /* param[0].size */
    char *json_data;     /* param[1].buffer */
    size_t json_data_sz; /* param[1].size */
    uint32_t data_flag;

    /* Safely get the invocation parameters */
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    json_hash_sz = params[0].memref.size;
    json_hash = TEE_Malloc(json_hash_sz, 0);
    if (!json_hash)
        return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(json_hash, params[0].memref.buffer, json_hash_sz);

    json_data_sz = params[1].memref.size;
    json_data = TEE_Malloc(json_data_sz, 0);
    if (!json_data)
        return TEE_ERROR_OUT_OF_MEMORY;

    data_flag =
        TEE_DATA_FLAG_ACCESS_READ | /* we can read the object */
        TEE_DATA_FLAG_SHARE_READ;   /* we can share the object with other TAs */

    /* Check if the object exist and open it for reading */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,     /* storageID */
        json_hash, json_hash_sz, /* objectID, objectIDLen */
        data_flag,               /* flags */
        &object                  /* object */
    );

    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to open persistent object, res=0x%08x", res);
        TEE_Free(json_hash);
        TEE_Free(json_data);
        return res;
    }

    res = TEE_GetObjectInfo1(object, &object_info);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to create persistent object, res=0x%08x", res);
        goto exit;
    }

    if (object_info.dataSize > data_sz)
    {
        /*
         * Provided buffer is too short.
         * Return the expected size together with status "short buffer"
         */
        params[1].memref.size = object_info.dataSize;
        res = TEE_ERROR_SHORT_BUFFER;
        goto exit;
    }

    res = TEE_ReadObjectData(
        object,               /* object */
        json_data,            /* buffer */
        object_info.dataSize, /* size */
        &read_bytes           /* counter */
    );

    /* Copy read data to output buffer */
    if (res == TEE_SUCCESS)
        TEE_MemMove(params[1].memref.buffer, json_data, read_bytes);

    if (res != TEE_SUCCESS || read_bytes != object_info.dataSize)
    {
        EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u", res, read_bytes, object_info.dataSize);
        goto exit;
    }

exit:
    TEE_CloseObject(object);
    TEE_Free(json_hash);
    TEE_Free(json_data);
    return res;
}

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

    /* Clean up */
    TEE_Free(object);
    return TEE_SUCCESS;
}

/**
 * Hash JSON object and store it in off-chain secure storage
 * @param param_types: expected parameter types
 * @param params: parameters passed to the TA
 */
static TEE_Result hash_json_object(uint32_t param_types, TEE_Param params[4])
{
    const uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    TEE_ObjectHandle object;
    TEE_Result res;
    char *json_data;       /* param[0].buffer */
    size_t json_data_sz;   /* param[0].size */
    char *hash_output;     /* param[1].buffer */
    size_t hash_output_sz; /* param[1].size */

    /*
     * Safely get the invocation parameters
     */
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    json_data_sz = params[0].memref.size;
    json_data = TEE_Malloc(json_data_sz, 0);
    if (!json_data)
        return TEE_ERROR_OUT_OF_MEMORY;
    TEE_MemMove(json_data, params[0].memref.buffer, json_data_sz);

    hash_output_sz = params[1].memref.size;
    hash_output = TEE_Malloc(hash_output_sz, 0);
    if (!hash_output)
        return TEE_ERROR_OUT_OF_MEMORY;

    /* Compute SHA256 hash of the JSON data */
    res = compute_sha256(json_data, json_data_sz, hash_output, &hash_output_sz);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to compute SHA256 hash, res=0x%08x", res);
        TEE_Free(json_data);
        TEE_Free(hash_output);
        return res;
    }

    /* Copy the hash output to the output parameter */
    if (hash_output_sz > params[1].memref.size)
    {
        /* Output buffer is too small */
        TEE_Free(json_data);
        TEE_Free(hash_output);
        TEE_Free(object);
        return TEE_ERROR_SHORT_BUFFER;
    }
    TEE_MemMove(params[1].memref.buffer, hash_output, hash_output_sz);
    params[1].memref.size = hash_output_sz;

    TEE_Free(json_data);
    TEE_Free(hash_output);
    TEE_Free(object);

    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to open persistent object, res=0x%08x", res);
        return res;
    }

    TEE_CloseAndDeletePersistentObject1(object);

    return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
    /* Nothing to do */
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

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session, uint32_t command, uint32_t param_types, TEE_Param params[4])
{
    if (TA_OFF_CHAIN_SECURE_STORAGE_STORE_JSON == command)
    {
        return store_json_object(param_types, params);
    }
    else if (TA_OFF_CHAIN_SECURE_STORAGE_RETRIEVE_JSON == command)
    {
        return retrieve_json_object(param_types, params);
    }
    else if (TA_OFF_CHAIN_SECURE_STORAGE_HASH_JSON == command)
    {
        return hash_json_object(param_types, params);
    }
    /*else if (TA_OFF_CHAIN_SECURE_STORAGE_GET_ATTESTATION == command)
    {
        return get_attestation(param_types, params);
    }
    else if (TA_OFF_CHAIN_SECURE_STORAGE_GET_PUBLIC_KEY == command)
    {
        return get_public_key(param_types, params);
    }*/
    else
    {
        EMSG("Command ID 0x%x is not supported", command);
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
