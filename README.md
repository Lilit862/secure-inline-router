# Secure Inline Network Communication Channel

A Linux-based prototype of a secure inline communication channel implementing a transparent security gateway architecture:
**`PC1 → Device1 (secure_sender) → Device2 (secure_receiver) → PC2`**

This project intercepts selected TCP/IPv4 traffic, performs a Diffie-Hellman key exchange to establish a secure session, encrypts TCP payloads using **AES-256-GCM**, recalculates IP and TCP pseudo-header checksums, and forwards traffic seamlessly without custom encapsulation headers.

---

## Architecture & Workflow

1. **PC1 (Source Client):** Generates standard plaintext TCP/IP traffic.
2. **Device 1 (`secure_sender.c`):** 
   - Intercepts incoming Ethernet frames via Linux raw sockets (`AF_PACKET`).
   - Executes a Diffie-Hellman key exchange handshake with Device 2.
   - Encrypts only the TCP payload using **AES-256-GCM** with a session-unique nonce derived from a packet counter.
   - Appends the 16-byte authentication tag, adjusts the IPv4 total length, and recalculates both the IP and TCP pseudo-header checksums.
3. **Device 2 (`secure_receiver.c`):**
   - Intercepts packets from Device 1.
   - Verifies the AES-GCM authentication tag and decrypts the TCP payload back to plaintext.
   - Restores the original packet structure and updates checksums.
   - Forwards the clean packet to **PC2**.
4. **PC2 (Destination Server):** Receives the original plaintext traffic securely.

---

## Features

- **Raw Socket Interception:** Operates at layer 2 (`AF_PACKET`) to intercept and inspect live network traffic.
- **Diffie-Hellman Handshake:** Dynamically negotiates secure shared session keys.
- **Authenticated Encryption:** Uses **AES-256-GCM** to provide both confidentiality and integrity (authenticity).
- **Replay Protection / Unique Nonces:** Guarantees a unique nonce for every packet within a session using packet counters.
- **Checksum Recalculation:** Accurately recomputes IPv4 header checksums and TCP pseudo-header checksums to ensure packet validity.

---

## Prerequisites

Ensure you have a Linux environment (Ubuntu VM recommended) with development tools and OpenSSL installed:

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev git
