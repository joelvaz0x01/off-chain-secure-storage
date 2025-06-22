# Off-Chain Data Storage using OP-TEE
Trusted Application for secure off-chain data storage

## Project Information
- **Course**: AES 2024/2025
- **Assignment**: #2 - Off-Chain Data Storage using OP-TEE
- **Authors**:
    - Hugo Silva - n.º 86157
    - Rúben Lopes - n.º 103009
    - Joel Vaz - n.º 124461


## Application Info and Usage

> [!NOTE]
> This is based on OP-TEE Sample Application [secure storage example](https://github.com/linaro-swg/optee_examples/tree/master/secure_storage).

| Application name         | UUID                                 |
| ------------------------ | ------------------------------------ |
| off_chain_secure_storage | e3ae8c32-5fc1-42e4-b476-b35fe3f8f07d |

```
Usage: ./off_chain_secure_storage <command>

Commands:
    retrieve <iot_device_id> - Retrieve JSON data for a given IoT device ID
    store <iot_device_id> <json_data> - Store JSON data for a given IoT device ID
    retrieve <json_hash> - Retrieve JSON data for a given hash
    hash <json_data> - Get SHA256 hash of a given JSON data
    attest - Get attestation data of the TA
    public-key - Get public key of the TA
```

## Project Description
This project implements a secure off-chain data storage solution using OP-TEE (Open Portable Trusted Execution Environment) for IoT sensor data management. The system main purpose is storing sensitive data off-chain while maintaining blockchain-level integrity and auditability through cryptographic hashing.


## Project Structure
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
├── iot-json/                     # Sample IoT data files
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

**QEMU Emulation Environment**

- ARM TrustZone simulation for development
- Secure and Normal World isolation


### Command Line Interface

The application provides the following commands:

#### 1. Store JSON File
```bash
./off_chain_secure_storage store <iot_device_id> <json_data>
```
**Purpose:** Securely store IoT sensor data with device identification  
**Response:** Returns the file ID (SHA-256 hash of contents)  
**Example:**
```bash
./off_chain_secure_storage store FARM001 '{"temperature": 24.5, "humidity": 65.2}'
```

#### 2. Retrieve JSON File  
```bash
./off_chain_secure_storage retrieve <json_hash>
```
**Purpose:** Retrieve stored data using the cryptographic hash  
**Response:** Returns the decrypted JSON file contents  
**Example:**
```bash
./off_chain_secure_storage retrieve a1b2c3d4e5f6789...
```

#### 3. Get File Hash
```bash
./off_chain_secure_storage hash <json_data>
```
**Purpose:** Generate SHA-256 hash without storing the file  
**Response:** Returns cryptographic hash for blockchain anchoring  
**Example:**
```bash
./off_chain_secure_storage hash '{"sensor_id": "ENV001", "reading": 42}'
```

#### 4. Get Digital Attestation
```bash
./off_chain_secure_storage attest
```
**Purpose:** Obtain cryptographic proof of TA authenticity  
**Response:** Returns RSA-PSS signature of TA UUID  

#### 5. Get Public Key
```bash
./off_chain_secure_storage public-key
```
**Purpose:** Extract TA's public key for signature verification  
**Response:** Returns RSA-2048 public key components


## Building and Installation

### Environment Setup

1. **Initialize OP-TEE Environment**
```bash
mkdir optee_workspace && cd optee_workspace
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
repo sync
```

2. **Build OP-TEE System**
```bash
cd build
make toolchains
make -j$(nproc)
```

### Project Integration

1. **Clone Project Repository**
```bash
git clone <repository_url>
```

2. **Integrate with OP-TEE Build System**
```bash
# Copy repository to OP-TEE examples
cp -r optee-offchain-storage $OPTEE_DIR/optee_examples/off_chain_secure_storage/

# Build the project
cd $OPTEE_DIR/build
make -j$(nproc)
```

## Running the Application

### Starting QEMU Environment
```bash
cd $OPTEE_DIR/build
make run-only
```

### Application Execution
1. Press `c` or type `cont` to start the OS
2. Login as `root` in Normal World console
3. Execute the application:
```bash
/usr/bin/off_chain_secure_storage --help
```


### Documentation Quick Reference

- **🚀 New to the project?** Start with this README
- **🔧 Setting up development environment?** See [BUILDING.md](documentation/BUILDING.md)
- **💻 Need API details or security specs?** Check [DOCUMENTATION.md](documentation/DOCUMENTATION.md)
- **🧪 Running tests or validation?** Reference [TESTING.md](documentation/TESTING.md)
- **🔍 Looking for specific implementation details?** Use [DOCUMENTATION.md](documentation/DOCUMENTATION.md) sections:
  - [API Documentation](documentation/DOCUMENTATION.md#api-documentation)
  - [Security Architecture](documentation/DOCUMENTATION.md#security-architecture)
  - [Cryptographic Specifications](documentation/DOCUMENTATION.md#cryptographic-specifications)
  - [Testing Guide](documentation/DOCUMENTATION.md#testing-guide)
  - [Development Workflow](documentation/DOCUMENTATION.md#development-workflow)



