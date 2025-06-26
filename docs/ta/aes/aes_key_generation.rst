.. _aes_key_generation:

Key Generation
=====================

This section describes how to generate and persist an AES key inside the Trusted Execution Environment (TEE).

- **Purpose:**  
  Generates a new AES key or retrieves an existing one from secure persistent storage.

- **Steps:**

  1. **Check for existing key:**  
     Uses ``TEE_OpenPersistentObject()`` to attempt opening the AES key object stored in TEE persistent storage.
     
     - If found, returns the key handle immediately.
     - If not found, proceeds to key generation.

  2. **Allocate transient AES object:**  
     Creates a volatile AES key object with ``TEE_AllocateTransientObject()``, specifying key size.

  3. **Generate random AES key:**  
     Generates the actual AES key material using ``TEE_GenerateKey()``.

  4. **Store key persistently:**  
     Saves the transient key object into persistent storage via ``TEE_CreatePersistentObject()``.

  5. **Error handling:**  
     On any failure, logs the error and frees allocated resources.

- **Notes:**

  - The key size is defined by ``AES_KEY_SIZE``.
  - Persistent storage used is ``TEE_STORAGE_PRIVATE``, ensuring the key is only accessible by the TA.

.. literalinclude:: ../../../ta/crypto_operations.c
   :language: c
   :lines: 124-197
   :linenos:
