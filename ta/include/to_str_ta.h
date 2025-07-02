#ifndef __TO_STR_TA_H__
#define __TO_STR_TA_H__

/*
 * UUID format: 8-4-4-4-12\0
 *
 * 8 + 4 + 4 + 4 + 12 = 32 characters
 * 32 + 4 dashes = 36 characters
 * 36 + 1 = 37 characters with null-terminator
 */
#define UUID_SIZE 37

/* Only available when building the TA code */
#ifdef TEE_INTERNAL_API_H
TEE_Result convert_to_hex_str(uint8_t *data, size_t data_sz, char *output_data_str, size_t output_data_str_sz);
TEE_Result uuid_to_str(char buffer[UUID_SIZE], TEE_UUID uuid);
#endif /* TEE_INTERNAL_API_H */

#endif /* __TO_STR_TA_H__ */
