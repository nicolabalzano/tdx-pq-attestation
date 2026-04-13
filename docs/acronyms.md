# Acronyms

This file explains the main acronyms used in the repository and in the ML-DSA TDX work.

## Core Platform Terms

| Acronym | Meaning | Short explanation |
|---|---|---|
| SGX | Software Guard Extensions | Intel trusted execution technology based on enclaves. |
| TDX | Trust Domain Extensions | Intel trusted execution technology for VMs / trust domains. |
| TEE | Trusted Execution Environment | A protected execution environment with isolation guarantees. |
| TD | Trust Domain | A protected VM under TDX. |
| VM | Virtual Machine | Standard virtualization unit; under TDX this becomes a protected TD. |

## Quote / Attestation Terms

| Acronym | Meaning | Short explanation |
|---|---|---|
| QE | Quoting Enclave | The enclave that produces quotes. In this repo the TDX quote flow uses TDQE. |
| TDQE | TDX Quoting Enclave | Repo-local trusted component that generates TDX quotes. |
| QGS | Quote Generation Service | Untrusted service/wrapper layer used to request quote generation. |
| QVL | Quote Verification Library | Parser and verifier library used to validate quotes. |
| QvE | Quote Verification Enclave | Trusted verifier enclave path used in some SGX/DCAP verification flows. |
| Quote | Attestation quote | Signed attestation object proving platform/report state. |
| Attestation key | Quote signing key | Key pair used by QE/TDQE to sign the quote. |
| `att_key_type` | Attestation key type | Quote header field identifying the signing algorithm/type. |

## Crypto / Algorithm Terms

| Acronym | Meaning | Short explanation |
|---|---|---|
| ECDSA | Elliptic Curve Digital Signature Algorithm | The standard existing quote-signing algorithm in Intel DCAP flows. |
| ML-DSA | Module-Lattice Digital Signature Algorithm | Post-quantum signature family used in this work. |
| MLDSA_65 | ML-DSA-65 | The specific ML-DSA parameter set introduced in this repo. |
| PQ | Post-Quantum | Refers to cryptography designed to resist quantum attacks. |
| SHA-256 | Secure Hash Algorithm 256-bit | Hash used here for key id / report-data binding checks. |
| RSA | Rivest-Shamir-Adleman | Public-key crypto used in legacy certification / PPID flows. |
| OAEP | Optimal Asymmetric Encryption Padding | RSA padding scheme used in legacy PCE-related certification flows. |

## DCAP / Collateral Terms

| Acronym | Meaning | Short explanation |
|---|---|---|
| DCAP | Data Center Attestation Primitives | Intel attestation stack for quote generation and verification outside EPID. |
| PCCS | Provisioning Certification Caching Service | Service that caches and serves collateral/certification data locally. |
| QCNL | Quote Config Network Library | Library used to fetch collateral/certification data from PCCS or remote services. |
| QPL | Quote Provider Library | Library used by quote generation to retrieve platform quote configuration/certification data. |
| PCS | Provisioning Certification Service | Remote Intel service that serves certification/collateral data. |
| Collateral | Verification collateral | TCB info, QE identity, CRLs, certificate chains, and related verification data. |
| Certification data | Quote certification payload | Certification material embedded in or attached to the quote flow. |
| PCK | Provisioning Certification Key | Platform certificate/key material used in standard DCAP verification flows. |
| PCK cert chain | PCK certificate chain | Certificate chain used by the standard verifier path. |
| CRL | Certificate Revocation List | Revocation data used during certificate validation. |
| CA | Certificate Authority | Entity issuing certificates in the verification chain. |

## SGX / TDX Identity / Versioning Terms

| Acronym | Meaning | Short explanation |
|---|---|---|
| PPID | Provisioning Platform ID | Platform identifier used in legacy SGX certification flows. |
| QEID | QE Identifier | Identifier associated with the quoting enclave. |
| FMSPC | Family-Model-Stepping-Platform-Custom SKU | Platform identifier used to retrieve TCB/collateral data. |
| TCB | Trusted Computing Base | Security-relevant platform/software version state. |
| TCBm | TCB measurement / TCB tuple | Repo discussions sometimes use this to refer to the platform TCB values returned with certification data. |
| CPU SVN | CPU Security Version Number | CPU security version used in certification and TCB checks. |
| PCE SVN | PCE Security Version Number | Security version of the Provisioning Certification Enclave. |
| ISV SVN | Independent Software Vendor Security Version Number | Software security version field used in SGX structures. |
| ISV | Independent Software Vendor | Vendor-defined software identity/version namespace in SGX metadata. |
| MRENCLAVE | Enclave measurement | Cryptographic measurement of enclave contents. |
| MRSIGNER | Signer measurement | Cryptographic identity of the enclave signer. |

## Repo / Build / Runtime Terms

| Acronym | Meaning | Short explanation |
|---|---|---|
| SDK | Software Development Kit | Here mainly the SGX SDK used to build/run trusted and untrusted pieces. |
| PSW | Platform Software | SGX runtime/platform software stack used by some legacy flows. |
| uRTS | Untrusted Runtime System | SGX untrusted runtime used to load and interact with enclaves. |
| EDL | Enclave Definition Language | Interface description used to generate enclave boundary code. |
| ECALL | Enclave Call | Call from untrusted code into enclave code. |
| OCALL | Outside Call | Call from enclave code out to untrusted host code. |
| HW | Hardware mode | Real hardware SGX/TDX execution mode. |
| SIM | Simulation mode | SGX simulation mode used for repo-local testing. |
| Blob | Persistent sealed state blob | Serialized and sealed QE/TDQE key state stored outside the enclave. |

## Components Referenced in This Work

| Acronym | Meaning | Short explanation |
|---|---|---|
| PCE | Provisioning Certification Enclave | SGX enclave used in legacy certification flows. |
| ID Enclave | Identity Enclave | Enclave used in the repo-local flow to retrieve identity-related data. |
| `libtdx_attest` | TDX attestation library | Public API layer used by direct TDX attestation callers. |
| `tee_att_*` | TEE attestation wrapper API | Repo wrapper API used by QGS and related quote-generation flows. |

## Practical Notes

- In the current ML-DSA work, `SIM` is used for repo-local generation and local verification testing.
- The standard verifier path depends on DCAP collateral and certification data.
- The local ML-DSA verifier fallback is only a simulation/test mechanism; it is not the standard production verifier path.
