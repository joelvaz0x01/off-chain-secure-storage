.. _rsa_get_public:

Retrieving RSA Public Key
===========================

This section documents how the Trusted Application (TA) securely retrieves the RSA public key from persistent storage.

Overview
--------

- **Purpose**: Provide the public part of the RSA key pair for external signature verification.
- **Format**: Concatenated modulus and exponent
- **Access**: Only public components are exposed; private key remains sealed

Steps
-----

1. **Validate Output Buffer**:
   
   - Ensures the caller's buffer is large enough to hold ``modulus + exponent``.

2. **Open Persistent RSA Key Object**:
   
   - Retrieves the private key object using ``TEE_OpenPersistentObject()``, which also contains public key parts.

3. **Extract Public Key Attributes**:
   
   - ``TEE_GetObjectBufferAttribute()`` is used to fetch:

     - **Modulus** (n)
     - **Public exponent** (e)


4. **Copy to Output Buffer**:
   
   - The function copies both parts into a single continuous output buffer.
   - Updates the length field to reflect actual data written.

Code Reference
--------------

.. literalinclude:: ../../../ta/crypto_operations.c
   :language: c
   :lines: 356-417
   :linenos:

Output Format
-------------

The final ``public_key`` buffer contains:

- **[0:n]** — RSA Modulus
- **[n:n+e]** — RSA Public Exponent

Total size is set via:

.. code-block:: c

   *public_key_len = mod_len + exp_len;

Usage
-----

The public key can be exported to the host system and used for:

- Verifying digital signatures from the TA
- Establishing trust between device and backend

Errors
------

- ``TEE_ERROR_SHORT_BUFFER``: Output buffer too small
- ``TEE_ERROR_ITEM_NOT_FOUND``: RSA key object missing
- ``TEE_ERROR_BAD_PARAMETERS``: Invalid buffer or flags
- ``TEE_SUCCESS``: Public key successfully retrieved
