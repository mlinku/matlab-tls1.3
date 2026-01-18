# TLS 1.3 Protocol Simulation in MATLAB

<p align="center">
  <img src="https://img.shields.io/badge/MATLAB-R2024a-orange?style=flat-square&logo=mathworks" alt="MATLAB">
  <img src="https://img.shields.io/badge/TLS-1.3-green?style=flat-square" alt="TLS 1.3">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
</p>

<p align="center">
  <b>A MATLAB-based simulation of TLS 1.3 protocol handshake authentication</b>
</p>

<p align="center">
  <a href="#introduction">Introduction</a> •
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#project-structure">Project Structure</a> •
  <a href="#usage">Usage</a> •
  <a href="#references">References</a> •
  <a href="README.md">中文</a>
</p>

---

## Introduction

> **Course Project**: This project is a course assignment for the graduate course "**Anti-Jamming and Secure Communication**" at **University of Electronic Science and Technology of China (UESTC)**.

This project implements a simulation of the **TLS 1.3 protocol** core handshake authentication process using **MATLAB**, focusing on the **key derivation chain** and **mutual certificate authentication mechanism**.

By building **client** and **server** objects in the MATLAB environment, combined with a series of cryptographic utility classes, this system successfully simulates the complete process from **Client Hello** message initiation to the exchange of **Finished** messages on both sides, ultimately exporting application-layer keys for actual data encryption.

### Highlights

- **Complete Handshake Flow**: Implements the full TLS 1.3 handshake from ClientHello to Finished
- **Wireshark Compatible**: Generates standard PCAP files and SSL Key Log for traffic analysis and decryption
- **Education Friendly**: Clear code structure, suitable for learning TLS 1.3 protocol principles

## Features

| Module | Status | Description |
|:-------|:------:|:------------|
| X25519 ECDHE Key Exchange | ✅ | Secure key negotiation based on elliptic curves |
| HKDF-SHA256 Key Derivation | ✅ | Complete key derivation chain implementation |
| AES-128-GCM Encryption | ✅ | Encryption protection for handshake messages |
| Mutual Certificate Auth (mTLS) | ✅ | Bidirectional identity verification |
| Certificate Verify | ✅ | RSA-PSS-RSAE-SHA256 signature verification |
| PCAP File Export | ✅ | Standard format, Wireshark compatible |
| SSL Key Log Generation | ✅ | Supports Wireshark decryption analysis |

### Implemented Handshake Messages

```
Client                                           Server

ClientHello
  + supported_versions
  + key_share
  + supported_groups
  + signature_algorithms  -------->
                                            ServerHello
                                          + key_share
                                   + supported_versions
                          <--------  {EncryptedExtensions}
                                     {CertificateRequest}
                                            {Certificate}
                                      {CertificateVerify}
                          <--------           {Finished}
{Certificate}
{CertificateVerify}
{Finished}                -------->
                          <=======>  [Application Data]
```

## Quick Start

### Requirements

- **MATLAB R2024a** or later (compatibility with other versions not tested)
- **Bouncy Castle** cryptographic library (`bcprov-jdk15on-1.70.jar`)

### Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/matlab-tls13.git
   cd matlab-tls13
   ```

2. **Prepare Certificate Files**

   > **Note**: The project includes self-signed test certificates, ready to run. To regenerate, use OpenSSL:

   ```bash
   # Generate server certificate and private key
   openssl req -x509 -newkey rsa:2048 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
   openssl x509 -in server_cert.pem -outform DER -out config/certificates/server/server_certificate.der
   openssl pkcs8 -topk8 -inform PEM -outform DER -in server_key.pem -out config/certificates/server/server_private_key_pkcs8.der -nocrypt

   # Generate client certificate and private key
   openssl req -x509 -newkey rsa:2048 -keyout client_key.pem -out client_cert.pem -days 365 -nodes
   openssl x509 -in client_cert.pem -outform DER -out config/certificates/client/client_certificate.der
   openssl pkcs8 -topk8 -inform PEM -outform DER -in client_key.pem -out config/certificates/client/client_private_key_pkcs8.der -nocrypt
   ```

3. **Run the Simulation**

   ```matlab
   % Execute in MATLAB
   cd src
   setup_environment
   main
   ```

### View Results

After execution, the following files will be generated in `src/output/`:

| File | Description |
|------|-------------|
| `tls13_handshake_simulation.pcap` | TLS handshake traffic capture file |
| `tls13_simulation_sslkeylog.txt` | SSL key log file |

## Project Structure

```
matlab-tls13/
├── src/                                # Source code directory
│   ├── main.m                          # Main program entry
│   ├── setup_environment.m             # Environment setup script
│   ├── PcapManager.m                   # PCAP file and TCP session manager
│   │
│   ├── output/                         # Output files directory
│   │   ├── tls13_handshake_simulation.pcap
│   │   └── tls13_simulation_sslkeylog.txt
│   │
│   ├── utils/                          # Utility classes directory
│   │   ├── ECDHEUtils.m                # X25519 ECDHE key exchange
│   │   ├── HKDFUtils.m                 # HKDF-SHA256 key derivation
│   │   ├── AES128Utils.m               # AES-128-GCM encryption/decryption
│   │   ├── RSAUtils.m                  # RSA key management and signing
│   │   ├── PcapWriterUtils.m           # PCAP packet construction
│   │   └── KeyLogFileUtils.m           # SSL key log generation
│   │
│   └── protocol/                       # Protocol endpoint implementation
│       ├── TLSProtocol.m               # TLS 1.3 protocol constants
│       ├── Client.m                    # Client implementation
│       └── Server.m                    # Server implementation
│
├── lib/                                # External dependencies
│   └── bcprov-jdk15on-1.70.jar         # Bouncy Castle crypto library
│
├── config/                             # Configuration resources
│   └── certificates/                   # Certificate and key storage
│       ├── server/                     # Server certificate and key
│       │   ├── server_certificate.der
│       │   └── server_private_key_pkcs8.der
│       └── client/                     # Client certificate and key
│           ├── client_certificate.der
│           └── client_private_key_pkcs8.der
│
├── LICENSE                             # MIT License
├── README.md                           # Project documentation (Chinese)
└── README_EN.md                        # Project documentation (English)
```

## Usage

### Wireshark Decryption Configuration

1. Open Wireshark
2. Go to `Edit > Preferences > Protocols > TLS`
3. Configure the `(Pre)-Master-Secret log filename` with the key log file path:
   ```
   /path/to/src/output/tls13_simulation_sslkeylog.txt
   ```
4. Open the `tls13_handshake_simulation.pcap` file
5. You can now view the decrypted TLS handshake messages

### Custom Configuration

To modify simulation parameters, edit the following files:

- `src/protocol/TLSProtocol.m` - Protocol constants and cipher suites
- `src/main.m` - Main program flow

## Technical Implementation

### Cryptographic Algorithms

| Algorithm | Purpose | Implementation |
|-----------|---------|----------------|
| X25519 | Key Exchange | Bouncy Castle |
| HKDF-SHA256 | Key Derivation | Bouncy Castle |
| AES-128-GCM | Encryption | Bouncy Castle |
| RSA-PSS-RSAE-SHA256 | Signature | Bouncy Castle |
| SHA-256 | Hash | Bouncy Castle |

### Key Derivation Flow

```
              0
              |
              v
    PSK ->  HKDF-Extract = Early Secret
              |
              +-----> Derive-Secret(., "ext binder" | "res binder", "")
              |                     = binder_key
              v
        Derive-Secret(., "c e traffic", ClientHello)
              |                     = client_early_traffic_secret
              v
        Derive-Secret(., "e exp master", ClientHello)
              |                     = early_exporter_master_secret
              v
        Derive-Secret(., "derived", "")
              |
              v
(EC)DHE -> HKDF-Extract = Handshake Secret
              |
              +-----> Derive-Secret(., "c hs traffic", ClientHello...ServerHello)
              |                     = client_handshake_traffic_secret
              +-----> Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
              |                     = server_handshake_traffic_secret
              v
        Derive-Secret(., "derived", "")
              |
              v
    0 -> HKDF-Extract = Master Secret
              |
              +-----> Derive-Secret(., "c ap traffic", ClientHello...server Finished)
              |                     = client_application_traffic_secret_0
              +-----> Derive-Secret(., "s ap traffic", ClientHello...server Finished)
                                    = server_application_traffic_secret_0
```

## References

### Protocol Specifications

- [RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

### Technical Articles

- [TLS 1.3 Handshake Process - Juejin](https://juejin.cn/post/7126911399304888357)
- [HTTPS Extensions - Halfrost's Blog](https://halfrost.com/https-extensions/)
- [TLS 1.3 Protocol Details - Tencent Cloud](https://cloud.tencent.com/developer/article/2123171)
- [TLS 1.3 Protocol Analysis - Zhihu](https://zhuanlan.zhihu.com/p/686461033)
- [TLS 1.3 Protocol Principles - NSFOCUS](https://blog.nsfocus.net/tls1-3protocol/)

### Development Tools

- [Bouncy Castle Crypto APIs](https://www.bouncycastle.org/)
- [Wireshark - Network Protocol Analyzer](https://www.wireshark.org/)

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

Issues and Pull Requests are welcome!

If you find this project helpful, please give it a Star ⭐

---

<p align="center">
  Made with ❤️ for learning TLS 1.3
</p>
