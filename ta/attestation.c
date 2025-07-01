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
 * This function generates and returns an attestation report containing:
 *   - TA UUID;
 *   - Counter value;
 *   - Nonce provided by the verifier;
 *   - SHA256 hash of the report;
 *   - RSA signature of the report.
 *
 * @param nonce Nonce provided by the verifier
 * @param sig_len Pointer to size of the signature buffer, will be updated with actual size
 * @param report_out Pointer to the attestation report structure to be filled
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result get_code_attestation(attestation_report_t *report_out, const uint8_t nonce[NONCE_SIZE])
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
    size_t hash_len = sizeof(report_out->hash);
    res = compute_sha256(data_to_hash, data_to_hash_sz, report_out->hash, &hash_len);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to compute SHA256 hash, res=0x%08x", res);
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

    /* Sign the SHA256 hash of the report */
    uint32_t signature_len = sizeof(report_out->signature);
    res = TEE_AsymmetricSignDigest(
        sign_op,               /* operation */
        NULL, 0,               /* params, paramsCount */
        report_out->hash,      /* digest */
        hash_len,              /* digestLen */
        report_out->signature, /* signature */
        &signature_len         /* signatureLen */
    );

    TEE_FreeOperation(sign_op);
    TEE_CloseObject(key_handle);

    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to sign attestation report, res=0x%08x", res);
        return res;
    }

    /* Fill the report structure */
    report_out->uuid = uuid;
    report_out->counter = counter;
    memcpy(report_out->nonce, nonce, NONCE_SIZE);

    return TEE_SUCCESS;
}
