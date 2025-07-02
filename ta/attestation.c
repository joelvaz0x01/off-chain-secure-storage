#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <secure_storage_ta.h>
#include <crypto_operations_ta.h>
#include <counter_ta.h>
#include <attestation_ta.h>

/**
 * Get code attestation report
 *
 * Generates the attestation report hash that includes:
 *   - TA UUID;
 *   - Counter value;
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
    TEE_UUID uuid = TA_OFF_CHAIN_SECURE_STORAGE_UUID;
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ;
    uint64_t counter;

    char data_to_hash[sizeof(uuid) + sizeof(counter) + NONCE_SIZE];
    size_t data_to_hash_sz = 0;

    uint8_t aux_hash[HASH_SIZE];
    size_t aux_hash_len = sizeof(aux_hash);

    uint8_t aux_signature[RSA_SIGNATURE_SIZE];
    uint32_t aux_signature_len = sizeof(aux_signature);

    char nonce_hex_str[NONCE_SIZE_HEX + 1] = {0};
    size_t nonce_hex_str_len = sizeof(nonce_hex_str);

    char hash_output[HASH_SIZE_HEX + 1] = {0};
    size_t hash_output_sz = sizeof(hash_output);

    char signature_output[RSA_SIGNATURE_SIZE_HEX + 1] = {0};
    size_t signature_output_sz = sizeof(signature_output);

    /* Get current counter value */
    res = get_counter(&counter);
    if (res != TEE_SUCCESS)
        return res;

    /* Build data to hash */
    memcpy(data_to_hash, &uuid, sizeof(uuid));
    data_to_hash_sz += sizeof(uuid);

    memcpy(data_to_hash + data_to_hash_sz, &counter, sizeof(counter));
    data_to_hash_sz += sizeof(counter);

    memcpy(data_to_hash + data_to_hash_sz, nonce, NONCE_SIZE);
    data_to_hash_sz += NONCE_SIZE;

    /* Compute SHA256 hash of the data */
    res = compute_sha256(data_to_hash, data_to_hash_sz, aux_hash, &aux_hash_len);
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

    /* Convert nonce to a hexadecimal string representation */
    res = convert_to_hex_str(nonce, NONCE_SIZE, nonce_hex_str, nonce_hex_str_len - 1);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to convert nonce to hex string, res=0x%08x", res);
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
    report_out->uuid = uuid;
    report_out->counter = counter;
    memcpy(report_out->nonce, nonce_hex_str, nonce_hex_str_len - 1);
    memcpy(report_out->hash, hash_output, hash_output_sz - 1);
    memcpy(report_out->signature, signature_output, signature_output_sz - 1);

exit:
    if (sign_op != TEE_HANDLE_NULL)
        TEE_FreeOperation(sign_op);
    if (key_handle != TEE_HANDLE_NULL)
        TEE_CloseObject(key_handle);

    return res;
}
