# Repo-Local SGXSSL Setup

These are the commands needed to bring up the local `QuoteVerification/sgxssl` tree from this repository layout, using the SDK already present in `tdx_tests/sgxsdk`.

```bash
cd /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteVerification

./prepare_sgxssl.sh
```

If `prepare_sgxssl.sh` stops because `unzip` is not installed, use these commands:

```bash
cd /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteVerification

python3 - <<'PY'
import zipfile, pathlib, shutil
base = pathlib.Path('/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteVerification/sgxssl')
zip_path = base / '3.0_Rev5.2.zip'
extract_root = base / 'intel-sgx-ssl-3.0_Rev5.2'
with zipfile.ZipFile(zip_path) as zf:
    zf.extractall(base)
for src in extract_root.iterdir():
    dst = base / src.name
    if dst.exists():
        if dst.is_dir():
            shutil.rmtree(dst)
        else:
            dst.unlink()
    shutil.move(str(src), str(dst))
shutil.rmtree(extract_root)
print('extracted')
PY

chmod +x \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteVerification/sgxssl/Linux/build_openssl.sh \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteVerification/sgxssl/Linux/prepare_openssl.sh

wget https://www.openssl.org/source/openssl-3.0.19.tar.gz \
  -O /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteVerification/sgxssl/openssl_source/openssl-3.0.19.tar.gz
```

Then build the local SGXSSL package:

```bash
cd /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteVerification/sgxssl/Linux

make sgxssl_no_mitigation SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

After that, return to the tests and run the TDX flow:

```bash
cd /home/alocin-local/tdx-pq-attestation/tdx_tests

sudo -E ./run_tdx_tests.sh
```
