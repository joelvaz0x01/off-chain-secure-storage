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

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <secure_storage_ta.h>

#define JSON_MAX_SIZE 7000       /* Maximum size of JSON data */
#define JSON_HASH_SIZE 32        /* Size of SHA256 hash (256 bits) */
#define ATTESTATION_DATA_SIZE 64 /* Size of Ed25519 signature (512 bits) */
#define PUBLIC_KEY_SIZE 32       /* Size of Ed25519 public key (256 bits) */

/* TEE resources */
struct test_ctx
{
    TEEC_Context ctx;
    TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
    TEEC_UUID uuid = TA_OFF_CHAIN_SECURE_STORAGE_UUID;
    uint32_t origin;
    TEEC_Result res;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx->ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    /* Open a session with the TA */
    res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
    TEEC_CloseSession(&ctx->sess);
    TEEC_FinalizeContext(&ctx->ctx);
}

/**
 * Retrieve JSON data in secure storage
 * @param ctx: pointer to the test context
 * @param json_hash: SHA256 hash of the JSON data
 * @param json_hash_len: length of the JSON hash
 * @param json_data: JSON data to be stored
 * @param json_data_len: length of the JSON data
 */
TEEC_Result retrieve_json_data(struct test_ctx *ctx, char *json_hash, size_t json_hash_len, char *json_data, size_t json_data_len)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,  /* param[0] (memref) */
        TEEC_MEMREF_TEMP_OUTPUT, /* param[1] (memref) */
        TEEC_NONE,               /* param[2] unused */
        TEEC_NONE                /* param[3] unused */
    );

    /* param[0] (memref) JSON hash to retrieve JSON data */
    op.params[0].tmpref.buffer = json_hash;
    op.params[0].tmpref.size = json_hash_len;

    /* param[1] (memref) Buffer to store the JSON data */
    op.params[1].tmpref.buffer = json_data;
    op.params[1].tmpref.size = json_data_len;

    res = TEEC_InvokeCommand(&ctx->sess, TA_OFF_CHAIN_SECURE_STORAGE_RETRIEVE_JSON, &op, &origin);

    /* If the buffer is too short, return the expected size */
    if (res == TEE_ERROR_SHORT_BUFFER)
    {
        printf("The provided buffer is too short, expected size: %zu\n", op.params[1].tmpref.size);
        return res;
    }

    if (res != TEEC_SUCCESS)
        printf("Command RETRIEVE_JSON failed: 0x%x / %u\n", res, origin);

    json_data = op.params[1].tmpref.buffer;
    json_data_len = op.params[1].tmpref.size;

    return res;
}

/**
 * Store JSON data from secure storage
 * @param ctx: pointer to the test context
 * @param iot_device_id: ID of the IoT device
 * @param json_data: buffer to store the retrieved JSON data
 * @param json_data_len: length of the JSON data buffer
 * @param json_hash: buffer to store the SHA256 hash of the JSON data
 * @param json_hash_len: length of the JSON hash buffer
 */
TEEC_Result store_json_data(struct test_ctx *ctx, char *iot_device_id, char *json_data, size_t json_data_len, char *json_hash, size_t json_hash_len)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;
    size_t iot_device_id_len = strlen(iot_device_id);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,  /* param[0] (memref) */
        TEEC_MEMREF_TEMP_OUTPUT, /* param[1] (memref) */
        TEEC_NONE,               /* param[2] unused */
        TEEC_NONE                /* param[3] unused */
    );

    /* param[0] (memref) IoT Device ID used the identify the persistent object */
    op.params[0].tmpref.buffer = iot_device_id;
    op.params[0].tmpref.size = iot_device_id_len;

    /* param[1] (memref) JSON data to be written in the persistent object */
    op.params[1].tmpref.buffer = json_data;
    op.params[1].tmpref.size = json_data_len;

    /* param[2] (memref) Buffer to store the SHA256 hash of the JSON data */
    op.params[2].tmpref.buffer = json_hash;
    op.params[2].tmpref.size = json_hash_len;

    res = TEEC_InvokeCommand(&ctx->sess, TA_OFF_CHAIN_SECURE_STORAGE_STORE_JSON, &op, &origin);

    if (res != TEEC_SUCCESS)
        printf("Command STORE_JSON failed: 0x%x / %u\n", res, origin);

    return res;
}

/**
 * Get SHA256 hash of JSON data
 * @param ctx: pointer to the test context
 * @param json_data: JSON data to be hashed
 * @param json_data_len: length of the JSON data
 * @param hash_output: buffer to store the SHA256 hash of the JSON data
 * @param hash_output_len: length of the hash output buffer
 */
TEEC_Result hash_json_data(struct test_ctx *ctx, char *json_data, size_t json_data_len, char *hash_output, size_t hash_output_len)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,  /* param[0] (memref) */
        TEEC_MEMREF_TEMP_OUTPUT, /* param[1] (memref) */
        TEEC_NONE,               /* param[2] unused */
        TEEC_NONE                /* param[3] unused */
    );

    /* param[0] (memref) JSON data to be hashed */
    op.params[0].tmpref.buffer = json_data;
    op.params[0].tmpref.size = json_data_len;

    /* param[1] (memref) Buffer to store the SHA256 hash of the JSON data */
    op.params[1].tmpref.buffer = hash_output;
    op.params[1].tmpref.size = hash_output_len;

    res = TEEC_InvokeCommand(&ctx->sess, TA_OFF_CHAIN_SECURE_STORAGE_HASH_JSON, &op, &origin);

    if (res != TEEC_SUCCESS)
        printf("Command HASH_JSON failed: 0x%x / %u\n", res, origin);

    return res;
}

/**
 * Get attestation data of the TA
 * @param ctx: pointer to the test context
 * @param attestation_data: buffer to store the attestation data
 * @param attestation_data_len: length of the attestation data buffer
 */
TEEC_Result get_attestation_data(struct test_ctx *ctx, char *attestation_data, size_t attestation_data_len)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_OUTPUT, /* param[0] (memref) */
        TEEC_NONE,               /* param[1] unused */
        TEEC_NONE,               /* param[2] unused */
        TEEC_NONE                /* param[3] unused */
    );

    /* param[0] (memref) Buffer to store the attestation data */
    op.params[0].tmpref.buffer = attestation_data;
    op.params[0].tmpref.size = attestation_data_len;

    res = TEEC_InvokeCommand(&ctx->sess, TA_OFF_CHAIN_SECURE_STORAGE_GET_ATTESTATION, &op, &origin);

    if (res != TEEC_SUCCESS)
        printf("Command GET_ATTESTATION failed: 0x%x / %u\n", res, origin);

    return res;
}

/**
 * Get public key of the TA
 * @param ctx: pointer to the test context
 * @param public_key: buffer to store the public key
 * @param public_key_len: length of the public key buffer
 */
TEEC_Result get_public_key(struct test_ctx *ctx, char *public_key, size_t public_key_len)
{
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_OUTPUT, /* param[0] (memref) */
        TEEC_NONE,               /* param[1] unused */
        TEEC_NONE,               /* param[2] unused */
        TEEC_NONE                /* param[3] unused */
    );

    /* param[0] (memref) Buffer to store the public key */
    op.params[0].tmpref.buffer = public_key;
    op.params[0].tmpref.size = public_key_len;

    res = TEEC_InvokeCommand(&ctx->sess, TA_OFF_CHAIN_SECURE_STORAGE_GET_PUBLIC_KEY, &op, &origin);

    if (res != TEEC_SUCCESS)
        printf("Command GET_PUBLIC_KEY failed: 0x%x / %u\n", res, origin);

    return res;
}

int main(void)
{
    struct test_ctx ctx;
    char json_data[JSON_MAX_SIZE];
    char hash_output[JSON_HASH_SIZE];
    char attestation_data[ATTESTATION_DATA_SIZE];
    char public_key[PUBLIC_KEY_SIZE];
    TEEC_Result res;

    /* List of commands available */
    if (argc < 3)
    {
        printf("Usage: %s <command>\n\n", argv[0]);
        printf("Commands:\n");
        printf("  store <iot_device_id> <json_data> - Store JSON data for a given IoT device ID\n");
        printf("  retrieve <json_hash> - Retrieve JSON data for a given hash\n");
        printf("  hash <json_data> - Get SHA256 hash of a given JSON data\n");
        printf("  attest - Get attestation data of the TA\n");
        printf("  public-key - Get public key of the TA\n");
        return 1;
    }

    printf("Prepare session with the TA\n");
    prepare_tee_session(&ctx);

    /* Command handling */
    if (0 == strcmp(argv[1], "store"))
    {
        strncpy(json_data, argv[3], JSON_MAX_SIZE);
        res = store_json_data(&ctx, argv[2], json_data, JSON_MAX_SIZE, hash_output, JSON_HASH_SIZE);
        if (res == TEEC_SUCCESS)
        {
            printf("SHA256 hash of the JSON data: ");
            for (size_t i = 0; i < JSON_HASH_SIZE; i++)
            {
                printf("%02x", (unsigned char)hash_output[i]);
            }
            printf("\n");
        }
        else
        {
            printf("Failed to store JSON data for IoT device ID: %s\n", argv[2]);
        }
    }
    else if (0 == strcmp(argv[1], "retrieve"))
    {
        strncpy(hash_output, argv[2], JSON_HASH_SIZE);
        res = retrieve_json_data(&ctx, hash_output, JSON_HASH_SIZE, json_data, JSON_MAX_SIZE);
        if (res == TEEC_SUCCESS)
        {
            printf("Retrieved JSON data: %s\n", json_data);
        }
        else
        {
            printf("Failed to retrieve JSON data for hash: %s\n", hash_output);
        }
    }
    else if (0 == strcmp(argv[1], "hash"))
    {
        strncpy(json_data, argv[2], JSON_MAX_SIZE);
        res = hash_json_data(&ctx, json_data, JSON_MAX_SIZE, hash_output, JSON_HASH_SIZE);
        if (res == TEEC_SUCCESS)
        {
            printf("SHA256 hash of the JSON data: ");
            for (size_t i = 0; i < JSON_HASH_SIZE; i++)
            {
                printf("%02x", (unsigned char)hash_output[i]);
            }
            printf("\n");
        }
        else
        {
            printf("Failed to hash JSON data\n");
        }
    }
    else if (0 == strcmp(argv[1], "attest"))
    {
        res = get_attestation_data(&ctx, attestation_data, ATTESTATION_DATA_SIZE);
        if (res == TEEC_SUCCESS)
        {
            printf("Attestation data: ");
            for (size_t i = 0; i < ATTESTATION_DATA_SIZE; i++)
            {
                printf("%02x", (unsigned char)attestation_data[i]);
            }
            printf("\n");
        }
        else
        {
            printf("Failed to get attestation data\n");
        }
    }
    else if (0 == strcmp(argv[1], "public-key"))
    {
        res = get_public_key(&ctx, public_key, PUBLIC_KEY_SIZE);
        if (res == TEEC_SUCCESS)
        {
            printf("Public key: ");
            for (size_t i = 0; i < PUBLIC_KEY_SIZE; i++)
            {
                printf("%02x", (unsigned char)public_key[i]);
            }
            printf("\n");
        }
        else
        {
            printf("Failed to get public key\n");
        }
    }
    else
    {
        printf("Unknown command: %s\n", argv[1]);
        return 1;
    }

    printf("\nWe're done, close and release TEE resources\n");
    terminate_tee_session(&ctx);
    return 0;
}
