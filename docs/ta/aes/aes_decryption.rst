.. _aes_decryption:

Decryption using CTR Mode
==============================

This section describes decrypting AES-CTR encrypted data within the TEE.

- **Purpose:**  
  Decrypts ciphertext encrypted by AES-CTR, retrieving plaintext.

- **Process Overview:**

  1. **Validate input size:**  
     Ensures ciphertext length is at least one AES block size to contain the IV.

  2. **Extract IV:**  
     Reads the IV from the first AES block-sized bytes of ciphertext.

  3. **Retrieve AES key:**  
     Obtains the key handle using ``generate_aes_key()``.

  4. **Allocate decrypt operation:**  
     Creates AES-CTR decryption operation via ``TEE_AllocateOperation()``.

  5. **Set operation key:**  
     Assigns the AES key to the operation.

  6. **Initialize cipher:**  
     Initializes the operation with extracted IV.

  7. **Decrypt ciphertext:**  
     Processes ciphertext (excluding IV) using ``TEE_CipherUpdate()``.

  8. **Update output length:**  
     Sets plaintext length to decrypted data size.

  9. **Cleanup:**  
     Frees operation and key handles, zeroes IV buffer.

- **Notes:**

  - The FIRST block of ciphertext contains the IV, which is critical for decryption.
  - Output buffer must be large enough to hold decrypted data.

.. literalinclude:: ../../../ta/crypto_operations.c
   :language: c
   :lines: 421-493
   :linenos:
