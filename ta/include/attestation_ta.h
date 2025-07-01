#ifndef __ATTESTATION_TA_H__
#define __ATTESTATION_TA_H__

#ifndef __CRYPTO_STORAGE_TA_H__
#include <crypto_operations_ta.h>
#endif /* __CRYPTO_STORAGE_TA_H__ */

#define NONCE_SIZE 32

typedef struct
{
#ifdef TEE_INTERNAL_API_H
    TEE_UUID uuid; /* TA UUID */
#else
    TEEC_UUID uuid; /* TA UUID */
#endif /* TEE_INTERNAL_API_H */

    uint64_t counter;                       /* Counter value */
    char nonce[NONCE_SIZE * 2];             /* Nonce for attestation */
    char hash[SHA256_HASH_SIZE * 2];        /* Hash of attestation report */
    char signature[RSA_SIGNATURE_SIZE * 2]; /* Signature of attestation report */
} attestation_report_t;

/* Only available when building the TA code */
#ifdef TEE_INTERNAL_API_H
TEE_Result get_code_attestation(attestation_report_t *report_out, uint8_t nonce[NONCE_SIZE]);
#endif /* TEE_INTERNAL_API_H */

#endif /* __ATTESTATION_TA_H__ */
