.. _teec_errors:

Error Handling (TEEC Errors)
============================

This section describes common error codes returned by the TEE Client API (TEEC), including their meanings and recommended recovery actions.

.. list-table::
   :header-rows: 1
   :widths: 25 15 30 30
   :class: longtable

   * - Error Code
     - Hex Value
     - Description
     - Recovery Action

   * - ``TEEC_ERROR_BAD_PARAMETERS``
     - ``0xFFFF0006``
     - Input parameters are invalid or not correctly formatted.
     - Verify argument types, values, and expected structure.

   * - ``TEEC_ERROR_ITEM_NOT_FOUND``
     - ``0xFFFF0008``
     - Requested object (e.g., file or key) does not exist in secure storage.
     - Ensure the hash or identifier is correct and the item has been stored.

   * - ``TEEC_ERROR_OUT_OF_MEMORY``
     - ``0xFFFF000C``
     - Memory allocation failed inside the TEE.
     - Retry with a smaller buffer size or after releasing resources.

   * - ``TEEC_ERROR_SHORT_BUFFER``
     - ``0xFFFF0010``
     - Output buffer provided by the client is too small to hold the result.
     - Increase the buffer size and reissue the request.
