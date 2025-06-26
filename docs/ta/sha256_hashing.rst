.. _sha256_hashing:

SHA-256 Hashing
===============

This section explains the use of **SHA-256 (Secure Hash Algorithm - 256 bits)** for hashing operations within the **Trusted Execution Environment (TEE)**.

Overview
--------

SHA-256 is a widely adopted cryptographic hash function that produces a fixed-size, 256-bit (32-byte) output from arbitrary-length input data. It is commonly used to ensure:

- **Data Integrity** — detecting unintended modifications
- **Authenticity** — verifying that the data has not been tampered with
- **Non-repudiation** — proving origin of data in cryptographic systems

In the context of a TEE, SHA-256 operations are securely executed to protect sensitive information from exposure or manipulation.

Constant Definition
-------------------

The size of the SHA-256 hash output is defined as:

.. code-block:: c

   #define SHA256_HASH_SIZE 32  // SHA-256 produces 32-byte (256-bit) hashes

Function: ``compute_sha256``
----------------------------

The hashing is implemented via the ``compute_sha256()`` function, which calculates the SHA-256 digest of an input buffer securely within the TEE.

.. literalinclude:: ../../ta/crypto_operations.c
   :language: c
   :lines: 9-50
   :linenos:

**Parameters:**

- ``data``: Pointer to the data to be hashed.
- ``data_sz``: Size of the input data (in bytes).
- ``hash_output``: Output buffer to store the hash.
- ``hash_output_sz``: On input, specifies the size of the output buffer. On return, contains the actual size of the hash (32 bytes).

**Returns:**

- ``TEE_SUCCESS`` on success
- Appropriate TEE error code on failure

Implementation Details
----------------------

1. **Output Buffer Size Check:**

   Ensures the output buffer is large enough for a 32-byte SHA-256 hash. If not, returns ``TEE_ERROR_SHORT_BUFFER``.

2. **Secure Operation Allocation:**

   Allocates a TEE operation handle for SHA-256 in digest mode using ``TEE_AllocateOperation()``.

3. **Hashing Execution:**

   - Initializes the hash with ``TEE_DigestUpdate()``
   - Finalizes and retrieves the digest with ``TEE_DigestDoFinal()``

4. **Cleanup:**

   Frees the operation handle using ``TEE_FreeOperation()`` to release secure resources.

Security Considerations
------------------------

- The hash operation is fully contained within the TEE.
- Memory bounds are validated to avoid overflows.
- The implementation leverages GlobalPlatform TEE Internal API standards.
