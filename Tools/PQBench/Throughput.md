# Measuring The Impact of Cryptographic Algorithms in Throughput

## 🧭 Overview
Throughput is a critical performance metric, but its meaning varies depending on the context:

**General Network Throughput:** Measures how much data is transferred over a secure connection per unit time.

**KEM Throughput:** Measures how many key encapsulation and decapsulation operations can be performed per second.

**Signature Algorithm Throughput:** Measures how many signing and verification operations can be performed per second.

Each of these has different implications for performance, scalability, and security in cryptographic systems.

## 🔐 General Network Throughput (with Cryptographic Overhead)
This measures the actual data transfer rate over a secure channel (e.g., TLS with post-quantum crypto), factoring in the overhead introduced by cryptographic operations.

### Metrics
- **Throughput (Mbps or Gbps):** Total data transferred per second.
- **Overhead (%):** Difference in throughput between encrypted and unencrypted channels. We can also compare between multiple algorithms.

### Example Scripts
```bash
# Example using iperf3 to measure network throughput
iperf3 -c <server_ip> -t 60

# Example using Wireshark to capture packets
wireshark -i eth0 -k

# Example using OpenSSL to establish a secure connection
openssl s_client -connect <server_ip>:443 -tls1_3
```

## 🔑 KEM Algorithm Throughput
This focuses on the rate of key encapsulation and decapsulation operations, which are critical during the handshake phase of secure communication.

### Metrics
- **Encapsulation throughput (ops/sec)**
- **Decapsulation throughput (ops/sec)**
- **Key size, ciphertext size, shared secret size**

### Example Scripts
```bash
# Example using PQC benchmarking tools
pqc_bench -kem <kem_algorithm>


# Example using OpenSSL with PQC extensions
openssl speed -seconds 5 mlkem1024
```
## ✍️ Signature Algorithm Throughput
This measures the performance of digital signature schemes, used for authentication and integrity.

### Metrics
- **Signing throughput (ops/sec)**
- **Verification throughput (ops/sec)**
- **Signature size, public/private key size**

### Example Scripts
```bash
# Example using PQC benchmarking tools
pqc_bench -sig <signature_algorithm>


# Example using OpenSSL with PQC extensions
openssl speed -seconds 5 --signature-algorithms 
```
## 📊 Suggested Evaluation Setup
| Metric Type          | Measurement Tool     | Units          | Notes                           |
|----------------------|----------------------|----------------|---------------------------------|
| Network Throughput   | iperf3, Wireshark    | Mbps / Gbps    | Use with and without encryption |
| KEM Throughput       | pqc_bench, openssl     | ops/sec        | Measure both encapsulation and decapsulation |
| Signature Throughput | pqc_bench, openssl    | ops/sec        | Measure signing and verification |
