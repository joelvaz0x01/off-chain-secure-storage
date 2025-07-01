.. _aes_encryption:

Encryption using CTR Mode
==============================

This section explains encrypting data using AES in Counter (CTR) mode within the TEE.

- **Purpose:**  
  Encrypts plaintext data with AES-CTR mode using a securely stored AES key.

- **Process Overview:**

  1. **Obtain AES key:**  
     Calls ``generate_aes_key()`` to get the key handle.

  2. **Allocate cipher operation:**  
     Creates an AES-CTR encryption operation with ``TEE_AllocateOperation()``, specifying encryption mode and key size.

  3. **Set operation key:**  
     Assigns the AES key to the operation via ``TEE_SetOperationKey()``.

  4. **Generate and prepend IV:**  
     Creates a random initialization vector (IV) of AES block size with ``TEE_GenerateRandom()``, stores it at the start of the ciphertext buffer.

  5. **Initialize cipher:**  
     Initializes the AES-CTR operation with the generated IV using ``TEE_CipherInit()``.

  6. **Encrypt data:**  
     Processes the plaintext into ciphertext (starting after IV) via ``TEE_CipherUpdate()``.

  7. **Update output length:**  
     Sets ciphertext length to the sum of IV size and encrypted data size.

  8. **Cleanup:**  
     Frees operation and closes key handles, zeroes sensitive buffers.

- **Notes:**

  - The first block of ciphertext contains the IV, which is critical for decryption.
  - Each ciphertext has a random IV to ensure uniqueness and security.
  - AES-CTR mode allows parallel encryption, making it efficient for stream data.

.. literalinclude:: ../../../ta/crypto_operations.c
   :language: c
   :lines: 304-360
   :linenos:
