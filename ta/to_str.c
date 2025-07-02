#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <to_str_ta.h>

/**
 * Convert binary data to a hexadecimal string representation
 *
 * This function converts binary data into a hexadecimal string format.
 * Each byte of the input data is represented by two hexadecimal characters.
 * The output buffer must be large enough to hold the hexadecimal string.
 *
 * @param data Pointer to the binary data to be converted
 * @param data_sz Size of the binary data in bytes
 * @param output_data_str Pointer to the output buffer where the hexadecimal string will be stored
 * @param output_data_str_sz Size of the output buffer in bytes
 */
TEE_Result convert_to_hex_str(uint8_t *data, size_t data_sz, char *output_data_str, size_t output_data_str_sz)
{
    /* Make sure output buffer size is enough: 2 chars per byte */
    if (output_data_str_sz != data_sz * 2)
    {
        EMSG("Output buffer is too small, expected: %lu, got: %zu", data_sz * 2, output_data_str_sz);
        return TEE_ERROR_SHORT_BUFFER;
    }

    for (size_t i = 0; i < data_sz; i++)
    {
        snprintf(&output_data_str[i * 2], 3, "%02x", data[i]);
    }

    return TEE_SUCCESS;
}

/**
 * Convert a UUID to a string representation
 *
 * This function converts a UUID structure into a standard string format:
 * 8-4-4-4-12 (hexadecimal digits)
 *
 * @param buffer Pointer to the output buffer where the UUID string will be stored
 * @param buffer_sz Size of the output buffer in bytes
 * @param uuid The UUID structure to be converted
 */
TEE_Result uuid_to_str(char buffer[UUID_SIZE], TEE_UUID uuid)
{
    snprintf(buffer, UUID_SIZE, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
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

    return TEE_SUCCESS;
}
