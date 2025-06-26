.. _hash:

Hash Implementation
===================

This section describes how SHA-256 hashing is implemented within the **Trusted Execution Environment (TEE)**.

Overview
--------

SHA-256 is a cryptographic hash function that transforms input data of arbitrary size into a fixed 256-bit (32-bytes) digest. It plays a vital role in maintaining:

- **Data Integrity** — Detects unintentional or malicious changes.
- **Authenticity** — Verifies the source of data.
- **Non-repudiation** — Ensures evidence of data origin in secure systems.

Within the TEE, SHA-256 is executed in a confined and trusted environment to ensure the confidentiality and reliability of cryptographic processes.

Constant Definition
-------------------

The following macro defines the size of a SHA-256 hash output:

.. code-block:: c

   #define SHA256_HASH_SIZE 32  // SHA-256 produces 32-bytes (256-bits) digests

Implementation
--------------

The SHA-256 functionality is encapsulated in the `compute_sha256()` function, which computes the hash of a given buffer within the TEE.

.. literalinclude:: ../../ta/crypto_operations.c
   :language: c
   :lines: 9-50
   :linenos:

**Function Parameters:**

- ``data``: Pointer to the input buffer.
- ``data_sz``: Size of the input data in bytes.
- ``hash_output``: Pointer to the buffer where the resulting hash will be stored.
- ``hash_output_sz``: Pointer to a variable holding the size of ``hash_output``; updated with the actual hash size (32 bytes) on success.

**Return Value:**

- ``TEE_SUCCESS`` on successful computation.
- Relevant error codes such as ``TEE_ERROR_SHORT_BUFFER`` if the output buffer is too small.

Implementation Breakdown
------------------------

1. **Buffer Size Validation**

   The function first checks whether ``hash_output`` is large enough to hold a 32-bytes SHA-256 digest. If not, it exits with ``TEE_ERROR_SHORT_BUFFER``.

2. **Operation Allocation**

   A cryptographic operation handle is allocated for SHA-256 using ``TEE_AllocateOperation()``, configured in digest mode.

3. **Digest Computation**

   - ``TEE_DigestUpdate()`` is used to feed the input data into the hashing engine.
   - ``TEE_DigestDoFinal()`` finalizes the computation and outputs the hash.

4. **Resource Cleanup**

   Regardless of success or failure, the function frees the operation handle via ``TEE_FreeOperation()`` to release all associated secure resources.
