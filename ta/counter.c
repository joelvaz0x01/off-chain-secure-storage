#include <inttypes.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <counter_ta.h>

/**
 * Load the counter state from persistent storage.
 *
 * This function will:
 *   1. Open the persistent object where the counter state is stored;
 *   2. Read the counter state from the object;
 *   3. Fill the provided state structure with the loaded data.
 *
 * If the counter is not initialized, it will return an error.
 *
 * @param state Pointer to the counter state structure to be filled
 * @return TEE_Result indicating success or failure
 */
TEE_Result load_counter(counter_state_t *state)
{
    TEE_ObjectHandle object;
    TEE_Result res;

    uint32_t flag = TEE_DATA_FLAG_ACCESS_READ; /* we can read the object */
    uint32_t read_bytes;

    /* Open the persistent object where the counter state is stored */
    res = TEE_OpenPersistentObject(
        TEE_STORAGE_PRIVATE,          /* storageID */
        COUNTER_STORAGE_NAME,         /* objectID */
        strlen(COUNTER_STORAGE_NAME), /* objectIDLen */
        flag,                         /* flags */
        &object                       /* object */
    );
    if (res != TEE_SUCCESS)
    {
        EMSG("Counter not initialized or failed to open persistent object, res=0x%08x", res);
        return res;
    }

    /* Read the counter state from the object */
    res = TEE_ReadObjectData(object, state, sizeof(*state), &read_bytes);
    TEE_CloseObject(object);

    if (res != TEE_SUCCESS || read_bytes != sizeof(*state))
    {
        EMSG("TEE_ReadObjectData failed 0x%08x, read %u over %zu", res, read_bytes, sizeof(*state));
        return TEE_ERROR_CORRUPT_OBJECT;
    }

    return TEE_SUCCESS;
}

/**
 * Save the counter state to persistent storage
 *
 * This function will:
 *   1. Create or overwrite the persistent object where the counter state is stored;
 *   2. Write the state passed as a parameter.
 *
 * @param state Pointer to the counter state structure to be saved
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result save_counter(const counter_state_t *state)
{
    TEE_ObjectHandle object;
    TEE_Result res;

    uint32_t flag = TEE_DATA_FLAG_OVERWRITE; /* we can overwrite the object */

    /* Create or open the persistent object where the counter state will be stored */
    res = TEE_CreatePersistentObject(
        TEE_STORAGE_PRIVATE,          /* storageID */
        COUNTER_STORAGE_NAME,         /* objectID */
        strlen(COUNTER_STORAGE_NAME), /* objectIDLen */
        flag,                         /* flags */
        TEE_HANDLE_NULL,              /* attributes */
        state,                        /* initialData */
        sizeof(*state),               /* initialDataLen */
        &object                       /* object */
    );
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to create persistent object, res=0x%08x", res);
        return res;
    }

    TEE_CloseObject(object);
    return TEE_SUCCESS;
}

/**
 * Update the counter based on elapsed time and a random factor
 *
 * This function will:
 *   1. Retrieve the current counter state;
 *   2. Calculate the elapsed time since the last update;
 *   3. Generate a random factor, and update the counter accordingly;
 *
 * If the counter is not initialized, it will be set accordingly.
 *
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result update_counter(void)
{
    TEE_Result res;
    TEE_Time now;
    counter_state_t state = {0};

    /*
     * Load the current counter state
     * If the counter is not initialized, it will be set
     */
    res = load_counter(&state);
    if (res != TEE_SUCCESS)
    {
        TEE_GetSystemTime(&now);
        state.counter = 0;
        state.last_update = now;
        res = save_counter(&state);
        if (res != TEE_SUCCESS)
        {
            EMSG("Failed to initialize counter state, res=0x%08x", res);
            return res;
        }
    }

    /* Get the current time */
    TEE_GetSystemTime(&now);

    /*
     * Compute elapsed time since last update
     * If no time has passed, return the current counter value
     */
    uint64_t elapsed = now.seconds - state.last_update.seconds;
    if (elapsed == 0)
        return TEE_SUCCESS;

    /*
     * Update counter by multiplying elapsed time with a random factor
     * By doing that, the counter will increase at a variable rate
     */
    state.counter += 1;
    state.last_update = now;

    /* Save the updated state */
    res = save_counter(&state);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to save counter state, res=0x%08x", res);
        return res;
    }

    return TEE_SUCCESS;
}

/**
 * Get the current counter value and last update time
 *
 * This function will:
 *   1. Load the current counter state;
 *   2. Fill the provided pointers with the counter value and last update time.
 *
 * @param counter_value Pointer to store the current counter value
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result get_counter(uint64_t *counter_value)
{
    TEE_Result res;
    counter_state_t state = {0};

    /* Load the current counter state */
    res = load_counter(&state);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to load counter state, res=0x%08x", res);
        return res;
    }

    /* Get the current counter value */
    *counter_value = state.counter;
    return TEE_SUCCESS;
}

/**
 * Get the last update timestamp of the counter
 *
 * This function will:
 *   1. Load the current counter state;
 *   2. Fill the provided timestamp pointer with the last update time.
 *
 * @param timestamp Pointer to store the last update time
 * @return TEE_Success on success, or another code if an error occurs
 */
TEE_Result get_counter_timestamp(TEE_Time *timestamp)
{
    TEE_Result res;
    counter_state_t state = {0};

    /* Load the current counter state */
    res = load_counter(&state);
    if (res != TEE_SUCCESS)
    {
        EMSG("Failed to load counter state, res=0x%08x", res);
        return res;
    }

    /* Get the last update timestamp */
    *timestamp = state.last_update;
    return TEE_SUCCESS;
}
