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
#ifndef __SECURE_STORAGE_H__
#define __SECURE_STORAGE_H__

/* UUID of the trusted application */
#define TA_OFF_CHAIN_SECURE_STORAGE_UUID \
    { 0xe3ae8c32, 0x5fc1, 0x42e4, \
        { 0xb4, 0x76, 0xb3, 0x5f, 0xe3, 0xf8, 0xf0, 0x7d } }

/**
 * Store JSON data in off-chain secure storage (persistent object)
 * @param param[0] (memref) IoT Device ID used the identify the persistent object
 * @param param[1] (memref) JSON data to be written in the persistent object
 * @param param[2] (memref) Buffer to store the SHA256 hash of the JSON data
 * @param param[3] unused
 */
#define TA_OFF_CHAIN_SECURE_STORAGE_STORE_JSON 0

/**
 * Retrieve JSON data from off-chain secure storage (persistent object)
 * @param param[0] (memref) JSON hash to retrieve JSON data
 * @param param[1] (memref) Buffer to store the JSON data
 * @param param[2] unused
 * @param param[3] unused
 */
#define TA_OFF_CHAIN_SECURE_STORAGE_RETRIEVE_JSON 1

/**
 * Get the SHA256 hash of a JSON data (persistent object)
 * @param param[0] (memref) JSON data to be hashed
 * @param param[1] (memref) Buffer to store the SHA256 hash of the JSON data
 * @param param[2] unused
 * @param param[3] unused
 */
#define TA_OFF_CHAIN_SECURE_STORAGE_HASH_JSON 2

/**
 * Get attestation of the TA
 * @param param[0] (memref) Buffer to store the attestation data
 * @param param[1] unused
 * @param param[2] unused
 * @param param[3] unused
 */
#define TA_OFF_CHAIN_SECURE_STORAGE_GET_ATTESTATION 3

/**
 * Get the public key of the TA
 * @param param[0] (memref) Buffer to store the public key
 * @param param[1] unused
 * @param param[2] unused
 * @param param[3] unused
 */
#define TA_OFF_CHAIN_SECURE_STORAGE_GET_PUBLIC_KEY 4

#endif /* __SECURE_STORAGE_H__ */
