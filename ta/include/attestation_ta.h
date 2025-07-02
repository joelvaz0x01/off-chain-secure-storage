#ifndef __ATTESTATION_TA_H__
#define __ATTESTATION_TA_H__

#ifndef __CRYPTO_STORAGE_TA_H__
#include <crypto_operations_ta.h>
#endif /* __CRYPTO_STORAGE_TA_H__ */

#ifndef __TO_STR_TA_H__
#include <to_str_ta.h>
#endif /* __TO_STR_TA_H__ */

#define NONCE_SIZE 32
#define NONCE_SIZE_HEX (NONCE_SIZE * 2)

/*
 * Attestation report structure
 *
 * Data sizes:
 *   - UUID: char[UUID_SIZE]
 *   - Counter: uint64_t
 *   - Nonce: uint8_t[NONCE_SIZE]
 *
 * This structure contains:
 *   - Data to hash: UUID + Counter + Nonce
 *   - Hash of the attestation report: SHA256
 *   - Signature of the attestation report: RSA signature
 */
typedef struct
{
    char data[(UUID_SIZE - 1) + sizeof(uint64_t) + NONCE_SIZE_HEX + 23 + 1]; /* Data to hash */
    char hash[HASH_SIZE_HEX + 1];                                            /* Hash of attestation report */
    char signature[RSA_SIGNATURE_SIZE_HEX + 1];                              /* Signature of attestation report */
} attestation_report_t;

/* Only available when building the TA code */
#ifdef TEE_INTERNAL_API_H
TEE_Result get_code_attestation(attestation_report_t *report_out, uint8_t nonce[NONCE_SIZE]);
#endif /* TEE_INTERNAL_API_H */

#endif /* __ATTESTATION_TA_H__ */
