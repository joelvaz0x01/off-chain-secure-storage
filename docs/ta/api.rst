.. _api:

API Documentation
=================

This section documents the Trusted Application (TA) interface exposed through the TEE Client API. The TA provides five main commands for secure off-chain storage and attestation.

---

Store JSON Data
----------------
**Command ID:** ``TA_OFF_CHAIN_SECURE_STORAGE_STORE_JSON``

**Purpose:**  
Securely store JSON data by encrypting it with AES and generating a SHA-256 hash for reference.

**C Function Parameters:**

.. literalinclude:: ../../ta/include/secure_storage_ta.h
   :language: c
   :lines: 35-42
   :linenos:

**Operation Flow:**

1. Allocate secure memory
2. Compute SHA-256 hash of input JSON data
3. Encrypt data using AES-CTR mode with a randomly generated IV
4. Store the encrypted payload in TEE persistent storage, keyed by the hash
5. Return the hash to the client as a reference handle

---

Retrieve JSON Data
-------------------
**Command ID:** ``TA_OFF_CHAIN_SECURE_STORAGE_RETRIEVE_JSON``

**Purpose:**  
Retrieve and decrypt previously stored JSON data using its SHA-256 hash as a lookup key.

**C Function Parameters:**

.. literalinclude:: ../../ta/include/secure_storage_ta.h
   :language: c
   :lines: 44-51
   :linenos:

**Operation Flow:**

1. Validate input hash and allocate secure buffers
2. Locate and open the object in TEE persistent storage using the hash
3. Read the encrypted data
4. Decrypt using stored AES key and IV
5. Return decrypted JSON data to client

**Error Conditions:**

- ``TEE_ERROR_ITEM_NOT_FOUND`` — No object found for given hash
- ``TEE_ERROR_SHORT_BUFFER`` — Provided buffer size is insufficient
- ``TEE_ERROR_OUT_OF_MEMORY`` — Failed to allocate memory for operation

---

Hash JSON Data
----------------
**Command ID:** ``TA_OFF_CHAIN_SECURE_STORAGE_HASH_JSON``

**Purpose:**  
Generate a SHA-256 hash from JSON data without storing it.

**C Function Parameters:**

.. literalinclude:: ../../ta/include/secure_storage_ta.h
   :language: c
   :lines: 53-60
   :linenos:

**Use Cases:**

- Blockchain anchoring (e.g., for off-chain data proofs)
- Verifying data integrity before or after transmission
- Pre-hashing content for comparison or deduplication

---

Get Attestation
----------------
**Command ID:** ``TA_OFF_CHAIN_SECURE_STORAGE_GET_ATTESTATION``

**Purpose:**  
Generate a cryptographic signature that attests to the identity of the Trusted Application (TA).

**C Function Parameters:**

.. literalinclude:: ../../ta/include/secure_storage_ta.h
   :language: c
   :lines: 62-69
   :linenos:

**Attestation Process:**

1. Compute SHA-256 hash of the TA's UUID
2. Sign the hash using an RSA-2048 private key with PSS (Probabilistic Signature Scheme) padding
3. Return the digital signature to the client

---

Get Public Key
---------------
**Command ID:** ``TA_OFF_CHAIN_SECURE_STORAGE_GET_PUBLIC_KEY``

**Purpose:**  
Retrieve the RSA public key associated with the TA for verifying signatures.

**C Function Parameters:**

.. literalinclude:: ../../ta/include/secure_storage_ta.h
   :language: c
   :lines: 71-78
   :linenos:

**Public Key Format:**

The returned public key is encoded as a hexadecimal string in the following format:

.. code-block:: c

   Public key: <HEXADECIMAL VALUE>
