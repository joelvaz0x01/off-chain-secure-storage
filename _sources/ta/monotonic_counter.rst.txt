.. _monotonic_counter:

Monotonic Counter
=================

This section describes the implementation of a **monotonic counter** inside the Trusted Execution Environment (TEE).  
A monotonic counter is a counter that strictly increases over time and is used to prevent replay attacks, track state changes, or maintain an immutable sequence of events within secure applications.

---

Overview
--------

The monotonic counter is stored persistently inside the TEE to guarantee its integrity and non-repudiability.  
The implementation provides functions to:

- Load the counter state from persistent storage,
- Save the counter state to persistent storage,
- Update the counter value based on elapsed time,
- Retrieve the current counter value.

---

Data Structures
---------------

The counter state is stored in a structure typically defined as:

.. code-block:: c

   typedef struct {
       uint64_t counter;          /* Current counter value */
       TEE_Time last_update;      /* Timestamp of last update */
   } counter_state_t;

---

Loading the Counter State
-------------------------

The function ``load_counter()`` is responsible for loading the counter's state from persistent storage:

- It opens a persistent object identified by a predefined storage name.
- Reads the stored counter state into the provided structure.
- Returns an error if the counter is not initialized or if data corruption occurs.

This ensures the counter state is preserved across reboots or power cycles.

.. literalinclude:: ../../ta/counter.c
   :language: c
   :lines: 21-54
   :linenos:

---

Saving the Counter State
------------------------

The function ``save_counter()`` saves the current counter state:

- Creates or overwrites the persistent storage object for the counter.
- Writes the provided counter state structure into persistent storage.
- Closes the object handle after successful write.

This operation guarantees the updated counter value is securely stored.

.. literalinclude:: ../../ta/counter.c
   :language: c
   :lines: 66-92
   :linenos:

---

Updating the Counter
--------------------

The function ``update_counter()`` performs the logic of advancing the monotonic counter:

1. It attempts to load the existing counter state.  
   - If the counter is uninitialized, it initializes it to zero and sets the last update timestamp to the current system time.

2. It obtains the current system time and calculates the elapsed time since the last update.

3. If time has passed, it increments the counter (in this implementation by a fixed increment of 1 per update call).  
   - This could be modified to include a random factor or other logic if desired.

4. Updates the last update timestamp to the current time.

5. Saves the new state persistently.

By tracking elapsed time and increasing the counter accordingly, this function ensures the counter strictly increases with time.

.. literalinclude:: ../../ta/counter.c
   :language: c
   :lines: 106-157
   :linenos:

---

Retrieving the Counter Value
----------------------------

The function ``get_counter()`` simply loads the current counter state and returns the counter value to the caller.  
This provides a reliable and consistent way to query the monotonic counter.

.. literalinclude:: ../../ta/counter.c
   :language: c
   :lines: 169-185
   :linenos:

---

Retrieving the Last Update Timestamp
------------------------------------

The function ``get_last_update_time()`` retrieves the timestamp of the last counter update.  
This will be used when doing the attestation to ensure the counter is not only increasing but also reflects the time of the last update.

.. literalinclude:: ../../ta/counter.c
   :language: c
   :lines: 197-213
   :linenos:

Security Considerations
-----------------------

- The counter cannot decrease, protecting against rollback attacks.
- Use of the TEE persistent storage API ensures counter state confidentiality and integrity.
- The counter update logic relies on secure system time provided by the TEE.
