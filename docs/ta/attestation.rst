.. _attestation:

Attestation Implementation
==========================

This section details the implementation of the **attestation report generation** process inside the Trusted Execution Environment (TEE). Attestation is a critical security function that enables a remote verifier to confirm the integrity and authenticity of the Trusted Application (TA) by verifying cryptographic evidence about its code and state.

---

Overview
--------

The attestation mechanism produces a signed report that includes:

- The **Trusted Application UUID** (universally unique identifier),
- A **monotonic counter** value to prevent replay attacks,
- A **nonce** (number used once) provided by the verifier to ensure freshness.

The report contains:

- The raw data (TA UUID + counter + nonce),
- A SHA-256 hash of this data,
- An RSA signature over the hash, proving the TA's identity and report integrity.

---

Implementation
--------------

The attestation report generation is implemented in the function ``generate_attestation_report()``.

.. literalinclude:: ../../ta/attestation.c
   :language: c
   :lines: 31-215
   :linenos:

**Function Parameters:**

- ``report_out``: Pointer to a structure where the attestation report will be stored.
- ``nonce``: A random nonce provided by the verifier to ensure the report's freshness.

**Return:**

- ``TEE_SUCCESS`` if the operation completes successfully,
- Otherwise, an appropriate TEE error code indicating failure.

---

Step-by-step Implementation Details
-----------------------------------

1. **Input Validation**

   The function begins by checking if the pointers ``nonce`` and ``report_out`` are valid to avoid null dereferences.

2. **Retrieve Monotonic Counter**

   Calls ``get_counter()`` to fetch the current monotonic counter value, which helps prevent replay attacks by ensuring each attestation is unique and sequential.

3. **Prepare Data for Hashing**

   The data to be hashed is constructed by concatenating:

   - The TA's UUID (``TEE_UUID`` type),
   - The current counter value (``uint64_t``),
   - The verifier's nonce (``NONCE_SIZE`` bytes).

   This concatenated data serves as the core attestation payload.

4. **Compute SHA-256 Hash**

   The concatenated data is hashed using the SHA-256 algorithm via the ``compute_sha256()`` function. This fixed-length hash summarizes the attestation data in a secure digest form.

5. **Load RSA Private Key**

   The function opens a persistent RSA key pair stored securely in the TEE persistent storage. This key will be used to sign the hash, providing cryptographic proof of the TA’s identity.

6. **Allocate RSA Signing Operation**

   Allocates a cryptographic operation handle configured for RSA signature generation using **RSASSA-PSS** padding with SHA-256, which provides probabilistic signature security.

7. **Set Signing Key**

   The RSA key handle is attached to the operation context.

8. **Sign the Hash**

   Using the RSA private key and the allocated operation handle, the SHA-256 hash is signed, producing a signature that guarantees the integrity and origin of the attestation report.

9. **Convert Binary Data to Hexadecimal**

   The nonce, hash, and signature are each converted into hexadecimal string representations for easy transmission and human-readable logging.

10. **Populate Attestation Report Structure**

    The final report is filled with:

    - The TA UUID,
    - The current counter value,
    - The hexadecimal nonce,
    - The hexadecimal hash,
    - The hexadecimal signature.

---

Security Considerations
-----------------------

- The attestation report generation takes place **entirely within the TEE**, preventing tampering from the normal world.
- Using a monotonic counter prevents replay attacks.
- The verifier's nonce ensures freshness of the attestation.
- RSA signatures using RSASSA-PSS with SHA-256 provide strong cryptographic guarantees.
- Converting sensitive binary data into hex strings prevents encoding issues during report transmission.
