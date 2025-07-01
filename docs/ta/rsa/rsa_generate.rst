.. _rsa_generate:

Key Pair Generation
===================

This section describes the generation and persistent storage of an RSA-2048 key pair in the Trusted Execution Environment (TEE).

Overview
--------

- **Key Type**: RSA-2048
- **Storage**: Persistent in TEE private storage
- **Security**: Private key remains inside the TEE
- **Lifecycle**:

  - Generated once on first launch
  - Reused for all future operations

Process
-------

1. **Check for Existing Key Pair**:
   
   - Uses ``TEE_OpenPersistentObject()`` to check for an already generated key pair.
   - If the object exists, returns early with ``TEE_SUCCESS``.

2. **Generate New Key Pair**:
   
   - Allocates a transient RSA keypair object (``TEE_AllocateTransientObject``).
   - Generates a key pair using ``TEE_GenerateKey()``.

3. **Persist the Private Key**:
   
   - Stores the generated key using ``TEE_CreatePersistentObject()``.
   - Ensures the key is retained securely across sessions.

4. **Cleanup**:
   
   - Frees temporary objects and handles.

Code Reference
--------------

.. literalinclude:: ../../../ta/crypto_operations.c
   :language: c
   :lines: 98-164
   :linenos:

Possible Results
----------------

- ``TEE_ERROR_ITEM_NOT_FOUND``: Expected on first launch
- ``TEE_ERROR_OUT_OF_MEMORY``: If memory allocation fails
- ``TEE_ERROR_ACCESS_CONFLICT``: If another handle is using the object
- ``TEE_ERROR_BAD_PARAMETERS``: Incorrect object attributes
- ``TEE_SUCCESS``: Key pair successfully generated and stored
