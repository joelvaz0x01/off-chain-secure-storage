# Off-Chain Data Storage using OP-TEE

# Project Information

- **Course**: AES 24/25
- **Assignment**: #2 - Off-Chain Data Storage using OP-TEE
- **Authors**: Joel Vaz (86157), Hugo Silva(124461), Rúben Lopes(103009)



> [!NOTE]
> This is based on OP-TEE Sample Application [secure storage](https://github.com/linaro-swg/optee_examples/tree/master/secure_storage) example.

## Application Info

| Application name         | UUID                                 |
| ------------------------ | ------------------------------------ |
| off_chain_secure_storage | e3ae8c32-5fc1-42e4-b476-b35fe3f8f07d |


# Project Description
This project implements a secure off-chain data storage solution using OP-TEE (Open Portable Trusted Execution Environment) for IoT sensor data management. The system main purpose is storing sensitive data off-chain while maintaining blockchain-level integrity and auditability through cryptographic hashing.

# Project Structure
```
optee-offchain-storage/
├── README.md                     # This file
├── LICENSE                       # Project license
├── Makefile                      # Build configuration
├── host/                         # Client Application (Normal World)
│   ├── main.c                    # Main CLI application
│   ├── Makefile                  # Host build configuration
│   └── include/
│       └── secure_storage_ta.h   # TA interface definitions
├── ta/                           # Trusted Application (Secure World)
│   ├── secure_storage_ta.c       # Main TA implementation
│   ├── include/
│   │   ├── secure_storage_ta.h         # TA header file
│   │   └── user_ta_header_defines.h    # TA configuration
│   ├── sub.mk                          # TA build configuration
│   └── Makefile                        # TA build rules
├── job.json/                     # Sample IoT data files
│   ├── environmental-monitoring.json
│   ├── healthcare-iot.json
│   └── industrial-iot.json
├── scripts/                      # Testing and utility scripts
│   ├── build.sh                  # Automated build script
│   ├── test.sh                   # Automated testing
│   └── demo.sh                   # Demonstration script
└── documentation/                # Additional documentation
    ├── BUILDING.md               # Build instructions
    ├── TESTING.md                # Testing procedures
    └── images/                   # Screenshots and diagrams
```

## Architecture
### System Components

**Trusted Application (TA)** - Runs in OP-TEE Secure World

- Secure data storage and retrieval
- Cryptographic operations (SHA-256 hashing)
- Key management and encryption
- Attestation services

**Client Application (CA)** - Runs in Normal World

- Command-line interface for user interactions
- Communication bridge to TA


