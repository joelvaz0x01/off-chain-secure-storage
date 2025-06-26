# Off-Chain Data Storage using OP-TEE
Trusted Application for secure off-chain data storage


## :page_facing_up: Project Overview
- **Course**: AES 2024/2025
- **Assignment**: #2 - Off-Chain Data Storage using OP-TEE
- **Authors**:
    - Hugo Silva - n.º 86157
    - Rúben Lopes - n.º 103009
    - Joel Vaz - n.º 124461

> [!NOTE]
> This is based on OP-TEE Sample Application [secure storage example](https://github.com/linaro-swg/optee_examples/tree/master/secure_storage).

| Application name         | UUID                                 |
| ------------------------ | ------------------------------------ |
| off_chain_secure_storage | e3ae8c32-5fc1-42e4-b476-b35fe3f8f07d |


## :clipboard: Project Description
This project implements a secure off-chain data storage solution using OP-TEE (Open Portable Trusted Execution Environment) for IoT sensor data management. The system main purpose is storing sensitive data off-chain while maintaining blockchain-level integrity and auditability through cryptographic hashing.


## :open_file_folder: Project Structure

```bash
optee-offchain-storage/
├── docs/      # Documentation files
│
├── host/             # Client Application (Normal World)
│   ├── main.c        # Main CLI application
│   └── Makefile
│
├── iot-json/      # Sample IoT data files
│
├── ta/                               # Trusted Application (Secure World)
│   ├── include/
│   │   ├── crypto_operations.h       # Functions and macros for cryptography
│   │   └── secure_storage_ta.h       # TA header file
│   │
│   ├── crypto_operations.c           # Main TA implementation
│   ├── secure_storage_ta.c           # Main TA implementation
│   ├── Makefile
│   ├── user_ta_header_defines.h      # TA configuration
│   └── sub.mk
│
├── Android.mk
├── CMakeLists.txt
├── LICENSE
├── Makefile            
└── README.md
```


## :computer: System Architecture

### Security Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Normal World                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │          Client Application (CA)                │    │
│  │  • Command parsing                              │    │
│  │  • TEE Client API calls                         │    │
│  │  • User interface                               │    │
│  └─────────────────────────────────────────────────┘    │
│                           │                             │
│                    TEE Client API                       │
│                           │                             │
└───────────────────────────┼─────────────────────────────┘
                            │ TrustZone Boundary
┌───────────────────────────┼─────────────────────────────┐
│                    Secure World                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │       Trusted Application (TA)                  │    │
│  │  • JSON data encryption/decryption              │    │
│  │  • SHA-256 hash computation                     │    │
│  │  • RSA key management                           │    │
│  │  • Persistent storage access                    │    │
│  │  • Digital attestation                          │    │
│  └─────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────┐    │
│  │           OP-TEE OS Services                    │    │
│  │  • Secure storage                               │    │
│  │  • Cryptographic operations                     │    │
│  │  • Memory management                            │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### System Components

**Trusted Application (TA)** - Runs in OP-TEE Secure World:
- Secure data storage and retrieval
- Cryptographic operations (SHA-256 hashing)
- Key management and encryption
- Attestation services

**Client Application (CA)** - Runs in Normal World:
- Command-line interface for user interactions
- Communication bridge to TA

**QEMU Emulation Environment**
- ARM TrustZone simulation for development:
- Secure and Normal World isolation

### Command Line Interface

The application provides the following commands:

---

1. Store JSON File

```bash
./off_chain_secure_storage store <iot_device_id> <json_data>
```

**Purpose:** Securely store IoT sensor data with device identification

**Response:** Returns the file ID (SHA-256 hash of contents)

**Example:**
```bash
./off_chain_secure_storage store FARM001 '{"temperature": 24.5, "humidity": 65.2}'
```

---

2. Retrieve JSON File

```bash
./off_chain_secure_storage retrieve <json_hash>
```

**Purpose:** Retrieve stored data using its SHA-256 hash

**Response:** Returns the decrypted JSON file contents

**Example:**
```bash
./off_chain_secure_storage retrieve 'a1b2c3d4e5f6789...'
```

---

3. Get File Hash

```bash
./off_chain_secure_storage hash <json_data>
```

**Purpose:** Generate SHA-256 hash without storing the file

**Response:** Returns cryptographic hash for blockchain anchoring

**Example:**
```bash
./off_chain_secure_storage hash '{"sensor_id": "ENV001", "reading": 42}'
```

---

4. Get Digital Attestation

```bash
./off_chain_secure_storage attest
```

**Purpose:** Obtain cryptographic proof of TA authenticity

**Response:** Returns RSA-PSS signature of TA UUID

---

5. Get Public Key
```bash
./off_chain_secure_storage public-key
```

**Purpose:** Extract TA's public key for signature verification

**Response:** Returns RSA-2048 public key components


## :wrench: Installation and Setup

### Prerequisites

```bash
export OPTEE_DIR=~/optee

# Create OP-TEE directory and initialize repository
mkdir $OPTEE_DIR && cd $OPTEE_DIR
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml
repo sync

# Build OP-TEE system
cd $OPTEE_DIR/build
make toolchains
make --jobs=$(nproc)

# Clone this project
cd $OPTEE_DIR/optee_examples
git clone https://github.com/detiuaveiro/assignement-2-proj2-86157_103009_124461.git optee-off-chain-storage

# Rebuild OP-TEE with the new project
cd $OPTEE_DIR/build
make --jobs=$(nproc)
```

### Running OP-TEE with built Application

Execute the following commands to run OP-TEE in QEMU:

```bash
cd $OPTEE_DIR/build
make run-only
```

Then follow these steps:
1. Press `c` or `cont` to start the QEMU emulation
2. Login as `root` in `Normal World` console

Now you can run the `off_chain_secure_storage` command in the QEMU terminal:

```
/usr/bin/off_chain_secure_storage <command>

Commands:
    store <iot_device_id> <json_data> - Store JSON data for a given IoT device ID
    retrieve <json_hash> - Retrieve JSON data for a given hash
    hash <json_data> - Get SHA256 hash of a given JSON data
    attest - Get attestation data of the TA
    public-key - Get public key of the TA
```


## :book: Documentation

To build the documentation, you will need to install Python and make the following commands:
```bash
# Install Python virtual environment
cd $OPTEE_DIR
python -m venv .venv
source .venv/bin/activate

# Build documentation
pip install -r docs/requirements.txt
sphinx-build -b html docs/ docs/_build/html
```

The documentation will be generated in the `_build/html` directory. You can open the `index.html` file in a web browser to view it.


## :link: References

1. [OP-TEE Documentation](https://optee.readthedocs.io/) - Official OP-TEE development guide
2. [TEE Internal Core API Specifications](https://globalplatform.org/specs-library/tee-internal-core-api-specification/) - Trusted application specifications
3. [TEE Client API Specification](https://globalplatform.org/wp-content/uploads/2010/07/TEE_Client_API_Specification-V1.0.pdf) - Client application specifications
