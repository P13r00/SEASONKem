# A BENCHMARK OF LIGHTWEIGHT POST QUANTUM CRYPTOGRAPHY
Piero Cianciotta

---

## STANDARDISATION BODIES

### NIST, United States
* Principal actor in the standardisation of PQC schemes
* Proposed Crystals-Kyber (ML-KEM) as Key Encapsulation Mechanism, and Crystals-Dilithium (ML-DSA), Falcon (FN-DSA), and SPHINCS+ (SLH-DSA) as Digital Signature Algorithms

### ETSI, Europe
* Evaluating different methods, more oriented towards migration and hybrid-cryptography. Aiming at incorporating PQC into protocols like TLS, 5G, and IoT Security Frameworks, planning to satndardise BIKE and FrodoKEM by 2027 for 5G networks.

### China and Japan
* Respectively aiming to standardise Lightweight Lattice-Based Cryptography by 2026, and NTRU Prime by 2028.

### ISO/IEC, Global
* Aligning their standards to the NIST recommendations. Planning to incorporate lattice-based and hash-based cryptography in future versions of ISO 14888 and ISO 18033.

*A Review on the Advances, Applications, and Future Prospects of Post-Quantum Cryptography in Blockchain and loT*

---

## QUANTUM SAFE ALGORITHMS FAMILIES

### Lattice-Based
* Cryptographic primitves involving Lattices.
* Is the most common base among the standardised algorithms by NIST including:
  * Kyber, Dilithium (Module Learning With Errors)
  * Falcon (NTRU)

### Hash-Based
* Cryptographic primitves involving hash functions. The standardised algorithm using this primitive is SPHINCS+, used for digital signatures.

### Code-Based
* NIST announced other Four Code-Based Candidates for the Round 4 of the standardisation process.
* The code-based Algorithms are:
  * BIKE, Classic McEliece, and HQC, all Key Encapsulation Methods. Of these, HQC was selected to provide more variation among algorithms

### Supersingular elliptic curve isogeny
* NIST included SIKE as a Supersingular Elliptic Curve Isogeny algorithm for the PQC Standardisation Round 4, but it was broken on a classical computer

*Quantum secure authentication and key agreement protocols for loT-enabled applications: A comprehensive survey and open challenges*

---

## ISSUES IN THE IMPLEMENTATION OF PQC IN IOT (1/2)

The issue in the implementation of Quantum Safe algorithms in resource constrained environments, lies in the fact that both the energy consumption and the key sizes are much higher than traditional cryptography.

A comprehensive Benchmark shows how the only viable Key Encapsulation Method in Resource Constrained Environments is Kyber, but it is still considerably slower than SoTA Lightweight Cryptography Algorithms, like Curve25519.

The topic of preferred Quantum Safe DSA is more nuanced, with both Falcon and Dilithium being optimal in different scenarios. Still, the comparison with traditional cryptograhphy shows a considerable gap in speed and Signature size.

*A novel lightweight hybrid cryptographic framework for secure smart card operations*

---

## ISSUES IN THE IMPLEMENTATION OF PQC IN IOT (2/2)

The other major issue, being addressed by some standardisation bodies such as NIST and ISO/IEC, is the necessity of backwards compatibility. The implementation of current Quantum Safe Technologies cannot disregard devices that might be currently in use, for example legacy devices in Medical or Industrial lot.

The final issue, is the underlying safety of Lattice-Based problems. The reliability of Lattice-Based problems as a safety measure is still not guaranteed (hence the NIST efforts to have a varied base), and the current protocols often rely on hybrid-cryptography stacks, combining Quantum Safe and traditional Encryption Algorithms.

*A novel lightweight hybrid cryptographic framework for secure smart card operations*

---

## CURRENT RESEARCH DIRECTIONS

There are several research direction in the scenario of Quantum Security in loT:
* QKD: Quantum Key Distribution
* Dedicated Hardware Accelerators, to make the computation of Lattice-Based problems easier
* Algorithmic Optimisation: Several libraries are trying to optimise the run-time of PQC Algorithms
* Implementation in current protocols: The implementation process in current protocols, such as TLS 1.3, is still under development
* Estabilishing new authentication protocols

*A Review on the Advances, Applications, and Future Prospects of Post-Quantum Cryptography in Blockchain and loT*

---

## RESEARCH QUESTIONS

I highlighted the following research questions after a systematic literature review:
* What are the current State of The Art Lightweight Classical cryptography algorithms that could be implemented in a Hybrid Cryptography Stack?
* How do different algorithms compare, in micro controllers with and without hardware acceleration for Advanced Encryption Standard?
* How does a Full Quantum Safe Stack (Kyber, Falcon, Dilithium) perform on different constrained loT devices? (eg. ESP32, RP2040, STM32)
* What are the most optimal PQC and Hybrid Lightweight cryptography stacks?
* How do different components, like hardware accelerators in the ESP32, and assembly optimisation in the ARM Cortex-M4, affect the choice of an Hybrid Cryptography stack?

And some possible additional research questions that could be answered after the benchmark:
* Is it possible to use different signature algorithms in the same Quantum Safe Stack, for communication between edge devices and Microcontrollers? (Using both Falcon and Dilithium to speed up Verification and Signature respectively)
* Is it possible to integrate different Authentication techniques and Cryptographic stacks in a protocol like the one proposed in *A novel hybrid authentication protocol utilizing lattice-based cryptography for lot devices in fog networks*

---

## CLASSICAL ENCRYPTION STACK

To have a comparison between Quantum Safe and Classical encryption, it is necessary to identify the most common and efficient algorithms in use. The candidates are the following:

* **Digital Signature:** Ed25519, ECDSA P-256
* **Key Exchange:** X25519, ECDH P-256
* **Key Derivation:** HKDF-SHA256, Ascon-Hash256, Ascon-CXOF128
* **Symmetric Encryption:** ChaCha20-Poly1305, AES-GCM-256, Ascon-80pq, PHOTON-Beetle-AEAD

Note: While immune to Shor's Algorithm, both Key Derivation and Symmetric Encryption functions are vulnerable to Grover's Algorithm, which is able to halve the security of a symmetric process. Because of this, the security requirements need to be increased.

---

## QUANTUM SAFE ENCRYPTION STACK

The primary target of the research is to find the optimal combination of different encryption algorithms to guarantee Quantum Safety throughout the whole communication process. The candidates are the following:

* **Digital Signature:** Dilithium, Falcon, Hybrid Approach
* **Key Exchange:** Kyber, Hybrid Approach
* **Key Derivation:** HKDF-SHA256, Ascon-CXOF128, Ascon-Hash256
* **Symmetric Encryption:** ChaCha20-Poly1305, AES-GCM-256, Ascon-80pq, PHOTON-Beetle-AEAD

Note: While immune to Shor's Algorithm, both Key Derivation and Symmetric Encryption functions are vulnerable to Grover's Algorithm, which is able to halve the security of a symmetric process. Because of this, the security requirements need to be increased.

*A Review on the Advances, Applications, and Future Prospects of Post-Quantum Cryptography in Blockchain and loT*

---

## Previous Benchmarks and Comparisons

| Previous Benchmarks and Comparisons | Platform | Algorithms | Strength | Limitation |
| :--- | :--- | :--- | :--- | :--- |
| Performance Evaluation of Quantum-Resistant TLS for Consumer IoT Devices | Raspberry Pi 4 | Quantum Safe DSA, ECDSA, RSA | Comparison over WF and BT | Not resource constrained |
| Performing Classical and Post-Quantum Cryptography on IoT Data: An Evaluation | Raspberry Pi 5 | Kyber512, RSA, AES | Compares Classical to PQC | Not resource constrained, not extensive |
| KEMTLS vs. Post-quantum TLS: Performance on Embedded Systems | ARM Cortex-M4F | QS implementations of TLS | Compares different TLS libraries | Only one platform, only NIST Ivl1 |
| A Practical Performance Benchmark of Post-Quantum Cryptography Across Heterogeneous Computing Environments <br><br> Integrating Post-Quantum Cryptography and Blockchain to Secure Low-Cost IoT Devices | ARM Cortex-A53 <br><br> ESP32 | Kyber, Falcon, Dilithium on different NIST levels <br><br> Dilithium5 | Shows different usecases for Falcon and Dilithium <br><br> Algorithm and device specific optimisation | Does not test hybrid schemes <br><br> Only one algorithm |
| Benchmarking NIST-Standardised ML-KEM and ML-DSA on ARM Cortex-M0+: Performance. Memory, and Energy on the RP2040 | ARM Cortex-M0+ | Kyber, Dilithium on different NIST levels | Comparison with the more optimised M4 platform | Not extensive |
| pqm4. Testing and Benchmarking NIST PQC on ARM Cortex-M4 <br> pqm4: Benchmarking NIST Additional Post-Quantum Signature Schemes on Microcontrollers | ARM Cortex-M4 | Quantum Safe KEM and DSA | Test of all NIST Candidates, Heavily optimised library | Only one platform |
| This Research Plan | ARM Cortex-M0+ <br> ARM Cortex-M4 (most optimised) <br> ESP32 (Hardware accelerators) | Lightweight Cryptography, Post Quantum Cryptography, Hybrid stack | Compares all the possible combinations for an Hybrid Stack, on various constrained platforms | Only simulated, No actual hardware |

---

## NEXT STEP IN THE RESEARCH

* **Find libraries implementing all the selected algorithms**
  * Ed25519, ECDSA (P-256), X25519, ECDH (P-256), HKDF-SHA256, ChaCha20-Poly1305, AES GCM-256: mbed TLS
  * Ascon-Hash256, Ascon-80pq: ascon-c
  * PHOTON-Beetle-AEAD: lwc-finalists / photon-beetle
  * Dilithium, Kyber, Falcon: liboqs
* **Select microcontrollers to execute tests on**
  * ESP32: 32bit Xtensa dual-core LX6, High Performance, has hardware accelerators
  * STM32: ARM Cortex-M4, Mid Performance, has the most optimised library, pqm4
  * RP2040: ARM Cortex-M0+, Low Performance
* **Find a benchmark platform for executing tests**
  * ESP32: Wokwi
  * ARM Cortex: Renode
* **Potential Issues:** Incorrect simulation of Hardware Acceleration, Memory usage, Power consumption, Timing
* **Identify the test metrics**
* **Write the code platform for the test**
* **Analyse and compare the results**

---

## POSSIBLE FINAL STRUCTURE OF THE RESEARCH

* **Introduction**
  * Lightweight Cryptography, Standardisation Process
  * Quantum Threat and Post Quantum Cryptography, Standardisation Process
* **Justification of Research Gap**
  * Similar Work (Analysis of Previous Benchmarks)
  * Research Goal
* **Benchmark**
  * Presentation and Justification of the selected algorithms for the comparison
  * Methodologies
  * Results and comparison
* **Conclusion**
  * Findings and future research questions
