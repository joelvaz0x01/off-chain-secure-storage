#ifndef __RANDOM_COUNTER_H__
#define __RANDOM_COUNTER_H__

/* Only available when building the TA code */
#ifdef TEE_INTERNAL_API_H
#define COUNTER_STORAGE_NAME "counterState"
#define MAX_RANDOM_MULTIPLIER 100

/** Counter state structure */
typedef struct
{
    uint64_t counter;
    TEE_Time last_update;
} counter_state_t;

TEE_Result load_counter(counter_state_t *state);
TEE_Result save_counter(const counter_state_t *state);
TEE_Result update_counter(void);
TEE_Result get_counter(uint64_t *counter_value);
#endif /* TEE_INTERNAL_API_H */

#endif /* __RANDOM_COUNTER_H__ */
