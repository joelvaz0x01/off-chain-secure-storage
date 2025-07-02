#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <secure_storage_ta.h>
#include <crypto_operations_ta.h>
#include <counter_ta.h>
#include <attestation_ta.h>
#include <to_str_ta.h>

/**
 * Get code attestation report
 *
 * Generates the attestation report hash that includes:
 *   - TA UUID;
 *   - Counter value;
 *   - Last counter timestamp;
 *   - Nonce provided by the verifier;
 *
 * Returns an attestation report containing:
 *   - All report data (UUID + counter + nonce);
 *   - SHA256 hash of report data;
 *   - RSA signature of the report.
 *
 * @param report_out Pointer to the attestation report structure to be filled
 * @param nonce Nonce provided by the verifier
 * @param session Pointer to the session context
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result get_code_attestation(attestation_report_t *report_out, uint8_t nonce[NONCE_SIZE])
{
    if (!nonce || !report_out)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_Result res;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle sign_op = TEE_HANDLE_NULL;
    char uuid[UUID_SIZE] = {0};
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ;
    uint64_t counter = 0;

    /* Auxiliary buffers for hash and signature */
    uint8_t aux_hash[HASH_SIZE];
    size_t aux_hash_len = sizeof(aux_hash);

    uint8_t aux_signature[RSA_SIGNATURE_SIZE];
    uint32_t aux_signature_len = sizeof(aux_signature);

    /* Get the TA UUID */
    TEE_UUID ta_uuid = TA_OFF_CHAIN_SECURE_STORAGE_UUID;

    /* Last counter timestamp */
    TEE_Time timestamp;

    /* Buffer for nonce hexadecimal representation */
    char nonce_hex_str[NONCE_SIZE_HEX] = {0};
    size_t nonce_hex_str_len = sizeof(nonce_hex_str);

    /* Buffer for attestation report hash */
    char hash_output[HASH_SIZE_HEX + 1] = {0};
    size_t hash_output_sz = sizeof(hash_output);

    /* Buffer for data to hash */
    char *data_to_hash = NULL;
    size_t data_to_hash_sz = 1; /* +1 for null terminator */

    /* Buffer for RSA signature */
    char signature_output[RSA_SIGNATURE_SIZE_HEX + 1] = {0};
    size_t signature_output_sz = sizeof(signature_output);

    /* Get current counter value */
    res = get_counter(&counter);
    if (res != TEE_SUCCESS)
        return res;

    /* Get the TA UUID */
    res = uuid_to_str(uuid, ta_uuid);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get TA UUID, res=0x%08x", res);
        return res;
    }

    /* Convert nonce to a hexadecimal string representation */
    res = convert_to_hex_str(nonce, NONCE_SIZE, nonce_hex_str, nonce_hex_str_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to convert nonce to hex string, res=0x%08x", res);
        goto exit;
    }

    /* Get the last counter timestamp (uint32_t) */
    res = get_counter_timestamp(&timestamp);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to get counter timestamp, res=0x%08x", res);
        return res;
    }

    /* Prepare data to hash */
    data_to_hash_sz += snprintf(
        NULL, 0,                                                        /* buffer, buffer_len */
        "{uuid:%s,counter:%" PRIu64 ",timestamp:%" PRIu32 ",nonce:%s}", /* format string */
        uuid, counter, timestamp.seconds, nonce_hex_str                 /* data_to_hash */
    );

    data_to_hash = TEE_Malloc(data_to_hash_sz, 0);
    if (!data_to_hash)
    {
        EMSG("Failed to allocate memory for data to hash");
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    /* Fill the data to hash buffer */
    snprintf(
        data_to_hash, data_to_hash_sz,                                  /* buffer, buffer_len */
        "{uuid:%s,counter:%" PRIu64 ",timestamp:%" PRIu32 ",nonce:%s}", /* format string */
        uuid, counter, timestamp.seconds, nonce_hex_str                 /* data_to_hash */
    );

    /* Compute SHA256 hash of the data */
    res = compute_sha256(data_to_hash, data_to_hash_sz - 1, aux_hash, &aux_hash_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to compute SHA256 hash, res=0x%08x", res);
        goto exit;
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
        goto exit;
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
        goto exit;
    }

    /* Set the key for the operation */
    res = TEE_SetOperationKey(sign_op, key_handle);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to set key for signing operation, res=0x%08x", res);
        goto exit;
    }

    /* Sign the SHA256 hash of the report */

    res = TEE_AsymmetricSignDigest(
        sign_op,           /* operation */
        NULL, 0,           /* params, paramsCount */
        aux_hash,          /* digest */
        aux_hash_len,      /* digestLen */
        aux_signature,     /* signature */
        &aux_signature_len /* signatureLen */
    );
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to sign attestation report, res=0x%08x", res);
        goto exit;
    }

    /* Convert report hash to a hexadecimal string representation */
    res = convert_to_hex_str(aux_hash, aux_hash_len, hash_output, hash_output_sz - 1);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to convert report hash to hex string, res=0x%08x", res);
        goto exit;
    }

    /* Convert signature to a hexadecimal string representation */
    res = convert_to_hex_str(aux_signature, aux_signature_len, signature_output, signature_output_sz - 1);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to convert signature to hex string, res=0x%08x", res);
        goto exit;
    }

    /* Fill the report structure */
    memcpy(report_out->data, data_to_hash, data_to_hash_sz);
    memcpy(report_out->hash, hash_output, hash_output_sz);
    memcpy(report_out->signature, signature_output, signature_output_sz);

exit:
    if (data_to_hash)
        TEE_Free(data_to_hash);
    if (sign_op != TEE_HANDLE_NULL)
        TEE_FreeOperation(sign_op);
    if (key_handle != TEE_HANDLE_NULL)
        TEE_CloseObject(key_handle);

    return res;
}
