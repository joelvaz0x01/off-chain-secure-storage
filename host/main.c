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
#include <unistd.h>
#include <fcntl.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <secure_storage_ta.h>
#include <crypto_operations_ta.h>
#include <attestation_ta.h>

#define DEVICE_ID_MAX_SIZE 64 /* Maximum size of IoT device ID */
#define JSON_MAX_SIZE 7000    /* Maximum size of JSON data */

/**
 * Storage data: "iot_device_<id>:<json_data>\0"
 * +12 for "iot_device_" and ":" prefix
 * +1 for null terminator
 */
#define STORE_MAX_SIZE (DEVICE_ID_MAX_SIZE + 12 + JSON_MAX_SIZE + 1)

/** TEE resources */
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
 * Print UUID in a human-readable format
 *
 * This function prints the UUID in the standard format:
 * 8-4-4-4-12 (hexadecimal digits).
 *
 * @param prefix A string to prefix the UUID output
 * @param uuid The UUID to print
 */
void printf_uuid(char *prefix, TEEC_UUID uuid)
{
    printf("%s%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
           prefix,
           uuid.timeLow,
           uuid.timeMid,
           uuid.timeHiAndVersion,
           uuid.clockSeqAndNode[0],
           uuid.clockSeqAndNode[1],
           uuid.clockSeqAndNode[2],
           uuid.clockSeqAndNode[3],
           uuid.clockSeqAndNode[4],
           uuid.clockSeqAndNode[5],
           uuid.clockSeqAndNode[6],
           uuid.clockSeqAndNode[7]);
}

/**
 * Generate a random nonce
 *
 * This function reads from /dev/urandom and generates a nonce of size NONCE_SIZE.
 *
 * @param nonce Buffer to store the generated nonce
 * @return 0 on success, -1 on error
 */
int generate_nonce(uint8_t nonce[NONCE_SIZE])
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        perror("Failed to open /dev/urandom");
        return -1;
    }

    ssize_t read_bytes = read(fd, nonce, NONCE_SIZE);
    close(fd);

    if (read_bytes != NONCE_SIZE)
    {
        fprintf(stderr, "Failed to read nonce from /dev/urandom\n");
        return -1;
    }

    return 0;
}

/**
 * Store JSON data from secure storage
 *
 * This function interacts with the TA to store JSON data securely.
 * It uses the IoT device ID to identify the persistent object in the TEE.
 * The JSON data is stored in a persistent object, and the SHA256 hash is retrieved.
 *
 * @param ctx Pointer to the test context
 * @param iot_device_id ID of the IoT device
 * @param json_data Buffer to store the retrieved JSON data
 * @param json_data_len Length of the JSON data buffer
 * @param json_hash Buffer to store the SHA256 hash of the JSON data
 * @param json_hash_len Length of the JSON hash buffer
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
        TEEC_MEMREF_TEMP_INPUT,  /* param[1] (memref) */
        TEEC_MEMREF_TEMP_OUTPUT, /* param[2] (memref) */
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
        fprintf(stderr, "Command STORE_JSON failed: 0x%x / %u\n", res, origin);

    return res;
}

/**
 * Retrieve JSON data in secure storage
 *
 * This function interacts with the TA to retrieve JSON data securely.
 * It uses the SHA256 hash of the JSON data to identify the persistent object in the TEE.
 * The JSON data of a given hash is retrieved, if it exists.
 *
 * @param ctx Pointer to the test context
 * @param json_hash SHA256 hash of the JSON data
 * @param json_hash_len Length of the JSON hash
 * @param json_data JSON data to be stored
 * @param json_data_len Length of the JSON data
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

    /* Check for specific error codes */
    if (res == TEEC_ERROR_SHORT_BUFFER || res == TEEC_ERROR_ITEM_NOT_FOUND)
    {
        return res;
    }
    else if (res != TEEC_SUCCESS)
        fprintf(stderr, "Command RETRIEVE_JSON failed: 0x%x / %u\n", res, origin);

    json_data = op.params[1].tmpref.buffer;
    json_data_len = op.params[1].tmpref.size;

    return res;
}

/**
 * Get SHA256 hash of JSON data
 *
 * This function interacts with the TA to compute the SHA256 hash of the provided JSON data.
 * It uses the JSON data as input and returns the SHA256 hash in the output buffer.
 * This does not store the JSON data on secure storage, it only computes the hash.
 *
 * @param ctx Pointer to the test context
 * @param json_data JSON data to be hashed
 * @param json_data_len Length of the JSON data
 * @param hash_output Buffer to store the SHA256 hash of the JSON data
 * @param hash_output_len Length of the hash output buffer
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
        fprintf(stderr, "Command HASH_JSON failed: 0x%x / %u\n", res, origin);

    return res;
}

/**
 * Get attestation data of the TA
 *
 * This function interacts with the TA to retrieve attestation data.
 * It generates a code attestation report containing the TA UUID, counter value, and the nonce provided by the verifier.
 * This will return the attestation data, with its SHA256 hash and RSA signature.
 *
 * @param ctx Pointer to the test context
 * @param attestation_data Buffer to store the attestation data
 * @param attestation_data_len Length of the attestation data buffer
 */
TEEC_Result get_attestation_data(struct test_ctx *ctx, attestation_report_t *attestation_data)
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

    /* param[0] (memref) Nonce provided by the verifier */
    uint8_t nonce[NONCE_SIZE];
    if (generate_nonce(nonce) != 0)
    {
        fprintf(stderr, "Failed to generate nonce\n");
        return TEEC_ERROR_GENERIC;
    }
    op.params[0].tmpref.buffer = nonce;
    op.params[0].tmpref.size = NONCE_SIZE;

    /* param[1] (memref) Buffer to store the attestation data */
    op.params[1].tmpref.buffer = attestation_data;
    op.params[1].tmpref.size = sizeof(attestation_report_t);

    res = TEEC_InvokeCommand(&ctx->sess, TA_OFF_CHAIN_SECURE_STORAGE_GET_ATTESTATION, &op, &origin);
    if (res != TEEC_SUCCESS)
        fprintf(stderr, "Command GET_ATTESTATION failed: 0x%x / %u\n", res, origin);

    return res;
}

/**
 * Get public key of the TA
 *
 * This function interacts with the TA to retrieve the public key used for attestation.
 * The public key is used to verify the attestation data.
 *
 * @param ctx Pointer to the test context
 * @param public_key Buffer to store the public key
 * @param public_key_len Length of the public key buffer
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
        fprintf(stderr, "Command GET_PUBLIC_KEY failed: 0x%x / %u\n", res, origin);

    return res;
}

int main(int argc, char *argv[])
{
    struct test_ctx ctx;
    char json_data[JSON_MAX_SIZE + 1] = {0};
    char hash_output[SHA256_HASH_SIZE * 2] = {0};
    attestation_report_t attestation_data;
    char public_key[RSA_PUBLIC_KEY_SIZE] = {0};
    TEEC_Result res;

    /* List of commands available */
    if (argc < 2)
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

    printf("Prepare session with the TA\n\n");
    prepare_tee_session(&ctx);

    /* Command handling */
    if (0 == strcmp(argv[1], "store") && 4 == argc)
    {
        char store_data[STORE_MAX_SIZE] = {0};

        if (strlen(argv[2]) > DEVICE_ID_MAX_SIZE || strlen(argv[3]) > JSON_MAX_SIZE)
        {
            fprintf(stderr, "Error: IoT device ID or JSON data exceeds maximum size:\n");
            fprintf(stderr, "  IoT device ID max size: %d, got: %zu\n", DEVICE_ID_MAX_SIZE, strlen(argv[2]));
            fprintf(stderr, "  JSON data max size: %d, got: %zu\n", JSON_MAX_SIZE, strlen(argv[3]));
            return 1;
        }

        int written = snprintf(store_data, STORE_MAX_SIZE, "iot_device_%s:%s", argv[2], argv[3]);
        if (written < 0 || written >= STORE_MAX_SIZE)
        {
            fprintf(stderr, "Error: Combined data exceeds maximum size.\n");
            return 1;
        }

        res = store_json_data(&ctx, argv[2], store_data, strlen(store_data), hash_output, SHA256_HASH_SIZE * 2);
        if (res == TEEC_SUCCESS)
        {
            printf("SHA256 hash of the JSON data: %s\n", hash_output);
        }
        else if (res == TEEC_ERROR_ACCESS_CONFLICT)
        {
            fprintf(stderr, "Error: The persistent object already exists.\n");
            return res;
        }
        else
        {
            fprintf(stderr, "Error: Failed to store JSON data for IoT device ID: %s\n", argv[2]);
        }
    }
    else if (0 == strcmp(argv[1], "retrieve") && 3 == argc)
    {
        memcpy(hash_output, argv[2], SHA256_HASH_SIZE * 2);
        res = retrieve_json_data(&ctx, hash_output, SHA256_HASH_SIZE * 2, json_data, JSON_MAX_SIZE);
        if (res == TEEC_ERROR_SHORT_BUFFER)
        {
            fprintf(stderr, "Error: The provided buffer is too short, expected size: %u\n", JSON_MAX_SIZE);
            return 1;
        }
        else if (res == TEEC_ERROR_ITEM_NOT_FOUND)
        {
            fprintf(stderr, "Error: No JSON data found for the provided hash.\n");
            return 1;
        }
        else if (res == TEEC_SUCCESS)
        {
            printf("Retrieved JSON data: %s\n", json_data);
        }
    }
    else if (0 == strcmp(argv[1], "hash") && 3 == argc)
    {
        strncpy(json_data, argv[2], JSON_MAX_SIZE);
        res = hash_json_data(&ctx, json_data, strlen(json_data), hash_output, SHA256_HASH_SIZE * 2);
        if (res == TEEC_SUCCESS)
        {
            printf("SHA256 hash of the JSON data: %s\n", hash_output);
        }
        else
        {
            fprintf(stderr, "Error: Failed to hash JSON data\n");
        }
    }
    else if (0 == strcmp(argv[1], "attest") && 2 == argc)
    {
        res = get_attestation_data(&ctx, &attestation_data);
        if (res == TEEC_SUCCESS)
        {
            printf("Attestation report:\n");
            printf_uuid("  TA UUID: ", attestation_data.uuid);
            printf("  Counter: %lu\n", attestation_data.counter);
            printf("  Nonce: %s\n", attestation_data.nonce);
            printf("  SHA256 hash: %s\n", attestation_data.hash);
            printf("  RSA signature: %s\n", attestation_data.signature);
        }
        else
        {
            fprintf(stderr, "Error: Failed to get attestation data\n");
        }
    }
    else if (0 == strcmp(argv[1], "public-key") && 2 == argc)
    {
        res = get_public_key(&ctx, public_key, RSA_PUBLIC_KEY_SIZE * 2);
        if (res == TEEC_SUCCESS)
            printf("Public key: %s\n", public_key);
        else
            fprintf(stderr, "Error: Failed to get public key\n");
    }
    else
    {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    printf("\nWe're done, close and release TEE resources\n");
    terminate_tee_session(&ctx);
    return 0;
}
