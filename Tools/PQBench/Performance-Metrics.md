# Metrics to Evaluate Cryptographic Algorithms

| Main Metric Category           | Sub Metric                  | 🔍 Why It Matters                                                                                                                                                                         | Measurement Scripts   |
|:-------------------------------|:----------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------------|
| 📡 Network Performance Metrics | 🚀 Throughput               | Post-quantum algorithms often increase key and ciphertext sizes, which can reduce throughput in secure channels.                                                                       | [Guide](#throughput)                        |
|                                | ⏱️ Latency                   | Latency affects the responsiveness of secure systems, especially during key exchange and authentication.                                                                               | [Guide](#latency)                          |
|                                | 📉 Packet Loss              | Packet loss can cause handshake failures, retransmissions, or degraded performance in secure communication channels—especially over UDP-based protocols.                               | [Guide](#packet-loss)                          |
|                                | 🔄 Jitter                   | High jitter can degrade the performance of secure real-time applications like encrypted voice, video, or control systems using protocols such as DTLS or SRTP.                         | [Guide](#jitter)                          |
|                                | 🔗 Interoperability         | Post-quantum algorithms must integrate seamlessly into diverse systems—ranging from embedded devices to cloud services—without breaking compatibility or requiring major rewrites.     | [Guide](#interoperability)                          |
|                                | 📈 Scalability              | Post-quantum algorithms often have larger keys and signatures. Systems must scale without significant performance degradation under load.                                              | [Guide](#scalability)                          |
| ⚙️ Computational Performance    | 🧠 Overall Performance      | Post-quantum algorithms can be computationally intensive. Profiling helps identify bottlenecks and assess suitability for constrained or high-performance environments.                | [Guide](#overall-performance)                         |
|                                | 🔑 Key Generation Time      | Key generation is a critical step in secure communications. PQC algorithms often have longer key generation times due to larger key sizes and more complex math.                       | [Guide](#key-generation-time)                         |
|                                | ✍️ Signature Generation Time | Signature generation speed affects authentication latency in secure protocols like TLS, SSH, and code signing.                                                                         | [Guide](#signature-generation-time)                         |
|                                | ✅ Verification Time        | Verification is often performed more frequently than signing (e.g., in certificate chains), so performance here is critical.                                                           | [Guide](#verification-time)                         |
|                                | 🔐 Encryption Time          | Encryption speed affects throughput and responsiveness in secure channels like TLS, VPNs, and encrypted storage.                                                                       | [Guide](#encryption-time)                         |
|                                | 🔓 Decryption Time          | Decryption speed is critical for real-time applications and secure data access.                                                                                                        | [Guide](#decryption-time)                         |
| 🔋 Energy Performance          | 🔋 Energy Consumption       | In IoT and embedded systems, energy efficiency is critical. Post-quantum algorithms may require more computation, which can significantly impact battery life and thermal performance. | [Guide](#energy-consumption)                         |


# 📡 Network Performance Metrics

These metrics assess how cryptographic systems behave under real-world network conditions. They are critical for evaluating PQC readiness in distributed, latency-sensitive, or bandwidth-constrained environments.

## Throughput


### 🛠️ How to Measure

1. Set up a **TLS server** using `OpenSSL` with the `oqsprovider` (liboqs).
2. Use `openssl s_client` to initiate a PQC handshake.
3. After the handshake, simulate encrypted data transfer using `qperf`.

### 🧪 Example

#### 1. Start the TLS server
```bash
openssl s_server -cert server_cert.pem -key server_key.pem \
  -www -tls1_3 -provider oqsprovider \
  -cipher OQS_KEM_DEFAULT:OQS_SIG_DEFAULT \
  -port 4433
```
#### 2. On the client, initiate handshake and measure throughput
```bash

# Terminal 1: Establish PQC TLS connection
openssl s_client -connect <server-ip>:4433 -tls1_3 -provider oqsprovider

# Terminal 2: Measure throughput
qperf <server-ip> tcp_bw
```
#### Sample output
```
tcp_bw:
    bw  =  112.34 MB/sec
```
**Explanation:** This output shows the TCP bandwidth measured during a PQC-secured session. Higher bandwidth means higher throughput indicates better performance under encryption and less impact from larger key/ciphertext sizes.

## Latency  

### 🛠️ How to Measure
1. Use openssl s_client to initiate a PQC handshake.
2. Measure the time taken for the handshake and initial response.
3. Use qperf to measure round-trip latency after the secure channel is established.
### 🧪 Example
#### 1. Start the TLS server
```bash
openssl s_server -cert server_cert.pem -key server_key.pem \
  -www -tls1_3 -provider oqsprovider \
  -cipher OQS_KEM_DEFAULT:OQS_SIG_DEFAULT \
  -port 4433
```

#### 2. On the client, measure latency
```bash

# Terminal 1: Establish PQC TLS connection and observe handshake time
openssl s_client -connect <server-ip>:4433 -tls1_3 -provider oqsprovider

# Terminal 2: Measure network latency
qperf <server-ip> tcp_lat
```

#### Sample output
```
tcp_lat:
    latency  =  0.123 ms
```
**Explanation:** This output shows the round-trip latency after establishing a PQC-secured connection. Lower latency is crucial for responsive key exchanges and secure communications.
## Packet Loss

Indicates the percentage of packets lost during transmission, which can disrupt cryptographic protocols that rely on complete and accurate data delivery.


### 🛠️ How to Measure

1. Set up a **TLS server** using `OpenSSL` with the `oqsprovider` (liboqs).
2. Use `openssl s_client` to initiate a PQC handshake.
3. Simulate encrypted UDP traffic using `qperf` and measure packet loss.

### 🧪 Example

#### 1. Start the TLS server
```bash
openssl s_server -cert server_cert.pem -key server_key.pem \
  -www -tls1_3 -provider oqsprovider \
  -cipher OQS_KEM_DEFAULT:OQS_SIG_DEFAULT \
  -port 4433
```
#### 2. On the client, initiate handshake and measure packet loss
```bash
# Terminal 1: Establish PQC TLS connection
openssl s_client -connect <server-ip>:4433 -tls1_3 -provider oqsprovider

# Terminal 2: Simulate UDP traffic and measure packet loss
qperf <server-ip> udp_bw -m 64 -t 10
```
This test sends 64-byte UDP packets for 10 seconds and reports any packet loss during transmission.

#### Sample output
```
udp_bw:
    send_bw  =  98.76 MB/sec
    recv_bw  =  97.45 MB/sec
    lost_packets = 3
```
**Explanation:** This output shows the UDP bandwidth and the number of lost packets. Packet loss can disrupt cryptographic handshakes and degrade performance in real-time secure protocols.
## Jitter

Measures the variability in packet arrival times, which can affect the stability of real-time cryptographic systems.

### 🛠️ How to Measure

1. Set up a **TLS server** using `OpenSSL` with the `oqsprovider` (liboqs).
2. Use `openssl s_client` to perform a PQC handshake.
3. Simulate real-time UDP traffic using `qperf` and measure jitter.

### 🧪 Example

#### 1. Start the TLS server
```bash
openssl s_server -cert server_cert.pem -key server_key.pem \
  -www -tls1_3 -provider oqsprovider \
  -cipher OQS_KEM_DEFAULT:OQS_SIG_DEFAULT \
  -port 4433
```
#### 2. On the client, initiate handshake and measure jitter
```bash
# Terminal 1: Establish PQC TLS connection
openssl s_client -connect <server-ip>:4433 -tls1_3 -provider oqsprovider

# Terminal 2: Measure UDP jitter
qperf <server-ip> udp_lat -m 64 -t 10
```
This test sends 64-byte UDP packets for 10 seconds and reports latency and jitter statistics.

#### Sample output
```
udp_lat:
    latency  =  0.234 ms
    jitter   =  0.045 ms
```
**Explanation:** This output shows the average latency and jitter for UDP packets. High jitter can impair real-time encrypted applications like VoIP or video over DTLS/SRTP.

## Interoperability

Assesses whether a cryptographic algorithm functions correctly across different platforms, libraries, and protocols.


### 🛠️ How to Measure

1. Implement the same PQC algorithm (e.g., Kyber or Falcon) using multiple cryptographic libraries (e.g., OpenSSL + liboqs, wolfSSL, BoringSSL).
2. Test secure communication between heterogeneous systems (e.g., Linux ↔ Windows, x86 ↔ ARM).
3. Validate handshake success, data integrity, and certificate verification across environments.

### 🧪 Example

- Use `openssl s_server` on a Linux machine with `oqsprovider`.
- Use `openssl s_client` on a Windows machine or ARM-based device with the same provider.
- Confirm successful TLS handshake and data exchange:
```bash
openssl s_client -connect <server-ip>:4433 -tls1_3 -provider oqsprovider
```

#### Sample output
```
CONNECTED(00000003)
---
Certificate chain
 0 s:CN = Falcon Test Cert
   i:CN = Falcon Test CA
---
SSL handshake has read 1234 bytes and written 567 bytes
Verification: OK
```
**Explanation:** This confirms a successful TLS handshake and certificate verification using a PQC algorithm. It demonstrates cross-platform compatibility and protocol compliance.

## Scalability
Evaluates how cryptographic performance changes as data volume, key size, or connection count increases.


### 🛠️ How to Measure
1. Use a test harness or script to simulate increasing:
    - Payload sizes (e.g., 1 KB → 1 MB)
    - Key sizes (e.g., Falcon-512 vs Falcon-1024)
    - Concurrent connections (e.g., 10 → 1000 clients)
    
2. Monitor:
    - CPU and memory usage
    - Handshake time
    - Throughput and latency
### 🧪 Example
Use a benchmarking script that loops over different key sizes and payloads:
```bash
for size in 512 1024; do
  openssl s_server -cert falcon-${size}_cert.pem -key falcon-${size}_key.pem \
    -www -tls1_3 -provider oqsprovider -port 4433 &
  sleep 2
  openssl s_client -connect <server-ip>:4433 -tls1_3 -provider oqsprovider < /dev/null
  pkill -f s_server
done
```
This test compares handshake performance between Falcon-512 and Falcon-1024 under identical conditions.

# ⚙️ Computational Performance

This section evaluates how efficiently a cryptographic algorithm performs in terms of speed and resource usage during key operations like key generation, signing, encryption, and verification.

---

## Overall Performance

Measures CPU cycles, memory usage, and runtime efficiency during cryptographic operations such as key generation, signing, and verification.


### 🛠️ How to Measure

Use tools like:
- `valgrind` (with `callgrind` or `massif`) for memory and instruction profiling.
- `perf` for CPU-level performance counters.

### 🧪 Example : 
- Measure Memory Usage with `valgrind --tool=massif`

```bash
# Generate a Falcon-512 key
openssl genpkey -provider oqsprovider -algorithm falcon512 -out falcon_key.pem

# Create a test message
echo "Post-Quantum Cryptography Test" > message.txt

# Profile memory usage during signature generation
valgrind --tool=massif \
  --massif-out-file=massif.out \
  openssl dgst -sha256 -sign falcon_key.pem -out signature.bin message.txt

# View memory usage summary
ms_print massif.out
```
This will generate a detailed report of function calls, instruction counts, and hotspots during the signing operation.
#### Sample output
```
==12345== Total heap usage: 1,234 allocs, 1,234 frees, 1.2MB allocated
==12345== Instruction fetches: 12,345,678
```
**Explanation:** This output summarizes memory allocations and instruction fetches during cryptographic operations. It helps evaluate memory efficiency and identify performance bottlenecks.

- Measure CPU Instructions with `valgrind --tool=callgrind`
```bash
valgrind --tool=callgrind \
  --callgrind-out-file=callgrind.out \
  openssl dgst -sha256 -sign falcon_key.pem -out signature.bin message.txt

# View CPU instruction profile
callgrind_annotate callgrind.out
```
#### Sample output
```==12345== Callgrind, a call-graph generating cache profiler
==12345== Copyright (C) 2002-2017, and GNU GPL'd, by Josef Weidendorfer et al.
==12345== Using Valgrind-3.21.0 and LibVEX; rerun with -h for copyright info
==12345== Command: openssl dgst -sha256 -sign falcon_key.pem -out signature.bin message.txt
==12345==
```
This output is minimal because the actual profiling data is written to the file **callgrind.out**. if you run :
```
callgrind_annotate callgrind.out
```
you will see a detailed breakdown like this: 
```--------------------------------------------------------------------------------
Profile data file 'callgrind.out' (creator: callgrind-3.21.0)
Events    : Ir
Events    : Instructions executed
--------------------------------------------------------------------------------
Ir
--------------------------------------------------------------------------------
1,234,567  PROGRAM TOTALS

Ir  file:function
--------------------------------------------------------------------------------
123,456  crypto/falcon/falcon_sign.c:falcon_sign
 98,765  crypto/evp/digest.c:EVP_DigestInit_ex
 87,654  crypto/evp/digest.c:EVP_DigestUpdate
 76,543  crypto/evp/digest.c:EVP_DigestFinal_ex
 65,432  crypto/evp/signature.c:EVP_DigestSignInit
 ...
```
**Explanation:** This output indicates that CPU instruction profiling was performed using Callgrind. The detailed report helps analyze hotspots and optimize cryptographic routines.
## Key Generation Time

Measures the time required to generate a cryptographic key.
### 🛠️ How to Measure

Use `openssl genpkey` with a post-quantum algorithm via the `oqsprovider`.

### 🧪 Example
```bash
# Generate a Falcon-512 key and measure time
time openssl genpkey -provider oqsprovider -algorithm falcon512 -out falcon_key.pem
```
#### Sample output
```
real    0m0.456s
user    0m0.412s
sys     0m0.044s
```
**Explanation:** This output shows the time taken to generate a Falcon-512 key. It includes real, user, and system time, which are useful for benchmarking key setup latency.

## Signature Generation Time
Measures the time required to generate a digital signature.

### 🛠️ How to Measure
Use openssl dgst to sign a message using a PQC private key.

### 🧪 Example:
```bash
# Create a test message
echo "Post-Quantum Cryptography Test" > message.txt

# Sign the message using Falcon-512
time openssl dgst -sha256 -sign falcon_key.pem -out signature.bin message.txt
```

#### Sample output
```
real    0m0.123s
user    0m0.110s
sys     0m0.013s
```
**Explanation:** This output shows the time taken to generate a digital signature using Falcon-512. Fast signing is important for authentication in secure protocols.

## Verification Time
Measures the time required to verify a digital signature.


### 🛠️ How to Measure
Use openssl dgst with the corresponding public key to verify the signature.

### 🧪 Example
```bash
# Extract the public key
openssl pkey -in falcon_key.pem -pubout -out falcon_pubkey.pem

# Verify the signature
time openssl dgst -sha256 -verify falcon_pubkey.pem -signature signature.bin message.txt
```
#### Sample output
```
real    0m0.098s
user    0m0.085s
sys     0m0.013s
```
**Explanation**: This output shows the time taken to verify a digital signature. Since verification is often more frequent (e.g., in certificate chains), efficiency here is critical.

## Encryption Time
Measures the time required to encrypt data using a symmetric cipher, typically after a PQC key exchange.


### 🛠️ How to Measure
Use openssl enc to simulate encryption with AES after a key exchange.

### 🧪 Example
```bash
# Create a plaintext file
echo "Sensitive data for encryption" > plaintext.txt

# Encrypt using AES-256-CBC
time openssl enc -aes-256-cbc -salt -in plaintext.txt -out encrypted.txt -k secretkey
```

#### Sample output
```
real    0m0.067s
user    0m0.060s
sys     0m0.007s
```
**Explanation:** This output shows the time taken to encrypt a file using AES-256-CBC. It reflects the performance of symmetric encryption after a PQC key exchange.

## Decryption Time
Measures the time required to decrypt data using a symmetric cipher.

### 🛠️ How to Measure
Use openssl enc -d to decrypt the previously encrypted file.

### 🧪 Example:
```bash
# Decrypt the file
time openssl enc -d -aes-256-cbc -in encrypted.txt -out decrypted.txt -k secretkey
```
#### Sample output
```
real    0m0.072s
user    0m0.065s
sys     0m0.007s
```
**Explanation:** This output shows the time taken to decrypt a file using AES-256-CBC. Decryption speed is essential for real-time access to secure content.

# 🔋 Energy Performance 

## Energy Consumption
Measures the amount of electrical energy consumed during cryptographic operations such as key generation, signing, or encryption.


### 🛠️ How to Measure

1. **Hardware-Based Measurement** (recommended for accuracy):
   - Use external power measurement tools like:
     - Monsoon Power Monitor
     - Otii Arc
     - USB power meters (e.g., INA219, USB-C testers)
   - Connect the device running the cryptographic operation to the power monitor.
   - Record energy usage (in mWh or Joules) during the operation.

2. **Software-Based Estimation** (for development boards or Linux-based systems):
   - Use tools like:
     - `powerstat` or `perf` (Linux)
     - `RAPL` interface on Intel CPUs (`/sys/class/powercap`)
     - `pmu-tools` or `perf stat` with energy counters


### 🧪 Example :
- Harware-based with Otti Arc or Monsoon

  1. Connect your IoT device or embedded board to the power monitor.
  2. Start logging power consumption.
  3. Run the cryptographic operation (e.g., signing or key generation).
  4. Stop logging and export the energy profile.
  Analyze the energy spike corresponding to the crypto operation to calculate total energy consumed.
- Software-Based on Linux:

```bash
# Measure energy consumption during Falcon-512 signing using perf (if supported)
perf stat -e power/energy-pkg/ \
  openssl dgst -sha256 -sign falcon_key.pem -out signature.bin message.txt
```

#### Sample output
```
Performance counter stats for 'openssl dgst ...':
     0.123456      power/energy-pkg/  Joules
       0.001234 seconds time elapsed
```
**Explanation:** This output shows the estimated energy consumption during a cryptographic operation. It uses CPU energy counters (e.g., Intel RAPL) to assess power efficiency.
⚠️ Note: This requires a CPU that supports Intel RAPL (Running Average Power Limit). For embedded boards, use external meters for accurate results.


---

For a detailed understanding of device categories, please refer to [Categories.md](https://github.com/comcast-spider/CARAF-Knowledge-Base/blob/evaluation-metrics/Others/Performance-evaluation/Use-Case-Catagories.md), which provides a comprehensive classification based on energy, performance, and security considerations. Additionally, to see how metrics are mapped to device categories and use cases, consult [Categories-vs-Metrics.md](https://github.com/comcast-spider/CARAF-Knowledge-Base/blob/evaluation-metrics/Others/Performance-evaluation/Catagories-vs-Metrics.md) for insights into what metrics apply to specific use cases.
