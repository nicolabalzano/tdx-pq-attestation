# ML-DSA Flow In The Same TDQE Model

This note explains how ML-DSA should fit into the same trust model already used today for ECDSA in the TDQE.

The key point is:
- you should not use an operating-system key
- you should not keep the ML-DSA private key outside the enclave in plaintext
- you should follow the same pattern already used for ECDSA:
  - derive key material inside the TDQE
  - seal the private key into a blob
  - reload that blob later
  - sign the quote inside the TDQE

## High-level trust chain

The intended ML-DSA flow should be:

```text
hardware/platform root trust
    ->
TDQE sealing key
    ->
derived ML-DSA seed
    ->
ML-DSA keypair generated inside TDQE
    ->
ML-DSA private key stored in sealed blob
    ->
blob reloaded and verified later
    ->
quote signed inside TDQE with ML-DSA
```

This is the same model already used for ECDSA.

## What should NOT happen

You should not do this:

```text
OS key store
    ->
load ML-DSA private key from the operating system
    ->
sign quote outside or logically outside the TDQE trust boundary
```

That would break the design used by the current attestation path.

## What should happen instead

### 1. Derive a deterministic seed inside the TDQE

For ECDSA, the current code derives an internal attestation seed from the enclave sealing key.

For ML-DSA, the equivalent design should be:

```text
TDQE sealing key
    ->
derive ML-DSA seed bytes
    ->
pass seed bytes to ML-DSA key generation
```

That means:
- the seed is internal to the TDQE
- the seed is not provided by the operating system
- the seed is not provided by the wrapper API

## 2. Generate the ML-DSA keypair inside the TDQE

Conceptually:

```text
seed
    ->
ML-DSA keygen
    ->
public key + private key
```

The public key becomes part of the quote identity and certification flow.

The private key stays inside enclave memory and then gets sealed.

## 3. Build the ML-DSA sealed blob

You need the ML-DSA equivalent of the current ECDSA blob layout:

```text
plaintext metadata:
  - ML-DSA public key
  - ML-DSA key id hash
  - authentication data
  - certification metadata
  - QE report / QE id / platform info

secret protected payload:
  - ML-DSA private key
  - any other secret state required by the ML-DSA implementation
```

Then seal it:

```text
sgx_seal_data(...)
    ->
ML-DSA sealed blob
```

## 4. Persist the blob outside the enclave

Just like ECDSA today:
- the wrapper keeps the blob in a buffer
- the blob may be written to persistent storage
- the blob itself is safe to store outside the enclave because it is sealed

This does not mean the OS owns the attestation key.
It only means the sealed container is stored outside the enclave.

## 5. Reload and verify the blob later

Before signing a quote:
- the wrapper reloads the sealed blob
- the TDQE verifies and unseals it
- the TDQE recovers the ML-DSA private key

Conceptually:

```text
read sealed blob
    ->
verify/unseal inside TDQE
    ->
recover ML-DSA private key
```

## 6. Sign the quote inside the TDQE

Once the TDQE has:
- the quote body
- the ML-DSA private key recovered from the sealed blob

then it should do:

```text
ML-DSA sign(quote_prefix_or_quote_body, private_key)
    ->
signature bytes
```

and write:
- `header.att_key_type = SGX_QL_ALG_MLDSA_65`
- ML-DSA public key into `attest_pub_key`
- ML-DSA signature into `sig`

inside the ML-DSA quote layout.

## 7. Verify internally for fault mitigation

The ECDSA path today signs and then verifies internally.

The ML-DSA path should do the same:

```text
ML-DSA sign(...)
ML-DSA verify(...)
```

If verification fails:
- clear the output signature
- return an error

## Simple comparison with ECDSA

### Current ECDSA model

```text
seal key
  ->
derive ECDSA attestation material
  ->
generate ECDSA keypair in TDQE
  ->
seal ECDSA private key in blob
  ->
reload blob later
  ->
sign quote in TDQE
```

### Intended ML-DSA model

```text
seal key
  ->
derive ML-DSA seed/material
  ->
generate ML-DSA keypair in TDQE
  ->
seal ML-DSA private key in blob
  ->
reload blob later
  ->
sign quote in TDQE
```