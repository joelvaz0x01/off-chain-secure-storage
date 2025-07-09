.. _aes:

AES Implementation
==================

This section describes how AES (Advanced Encryption Standard) is implemented inside the Trusted Execution Environment (TEE).

AES is a symmetric-key algorithm widely used for data confidentiality. Within the TEE, AES keys are securely generated, stored, and used for encrypting and decrypting data using the AES-CTR (Counter) mode.

The following constants define AES parameters used throughout the implementation:

.. code-block:: c

   #define AES_KEY_STORAGE_NAME "aesKey"  // Identifier for key in secure storage
   #define AES_BLOCK_SIZE       16        // Block size for AES (128 bits)
   #define AES_KEY_SIZE         256       // AES key size in bits

.. toctree::
   :maxdepth: 1

   aes_key_generation
   aes_encryption
   aes_decryption
