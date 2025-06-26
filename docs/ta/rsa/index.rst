.. _rsa:

RSA Implementation
==================

This section provides an overview of RSA implementation within the Trusted Execution Environment (TEE).

RSA is a public-key cryptosystem used for secure data exchange, digital signatures, and key encapsulation. Within the TEE, RSA keys are generated, securely stored, and can be exported in a controlled manner for verification or encryption outside the TEE.

The following macros define key parameters for RSA key handling in the TEE implementation:

.. code-block:: c

   #define RSA_KEYPAIR_STORAGE_NAME     "rsaKeyPair"                           // Persistent storage ID for private key
   #define RSA_PUBLIC_KEY_STORAGE_NAME  "rsaPublicKey"                         // Persistent storage ID for public key
   #define RSA_KEY_SIZE_BITS            2048                                   // RSA key size in bits
   #define RSA_MODULUS_SIZE             (RSA_KEY_SIZE_BITS / 8)                // Size of the RSA modulus in bytes
   #define RSA_EXPONENT_SIZE            4                                      // Size of the RSA public exponent in bytes
   #define RSA_PUBLIC_KEY_SIZE          (RSA_MODULUS_SIZE + RSA_EXPONENT_SIZE) // Size of the public key (modulus + exponent)
   #define RSA_SIGNATURE_SIZE           (RSA_KEY_SIZE_BITS / 8)                // Size of the RSA signature

.. toctree::
   :maxdepth: 1

   rsa_generate
   rsa_get_pub
