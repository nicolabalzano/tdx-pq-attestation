# New Machine SGX/TDX/PCCS Bring-Up

This note records the machine bring-up work done after moving the repository to the new bare-metal host.

It is not a generic Intel guide. It is the concrete path that got this machine from:

- bare-metal Ubuntu 24.04 host
- SGX visible
- no active TDX host stack
- no working host quote generation

to:

- TDX host active
- TDX guest booting
- host `qgsd` and `pccs` working
- direct `ECDSA` quote generation working in the guest

## 1. Initial state on the new machine

Observed early on:

- the host was bare metal, not a TDX guest
- `/dev/tdx_guest` was absent on the host
- `/dev/sgx_enclave`, `/dev/sgx_provision`, `/dev/sgx_vepc` were present
- `dmesg | grep -i tdx` was empty
- `/sys/module/kvm_intel/parameters/tdx` did not exist

Important distinction:

- a bare-metal host with TDX-capable hardware is not the same thing as a TDX guest
- `/dev/tdx_guest` appears inside the guest, not on the host

## 2. BIOS / firmware prerequisites

The host BIOS had to be configured for TDX. The exact menu names depend on the platform, but the effective settings were:

- `SGX = Enable`
- `TME = Enable`
- `TME-MT = Enable`
- `TDX = Enable`
- `SEAM Loader = Enable`
- non-zero TDX/TME key split

Without this, the host kernel never exposed the TDX host stack.

## 3. Host TDX enablement on Ubuntu 24.04

This machine stayed on Ubuntu 24.04, so the working path was the Canonical TDX host setup rather than a stock generic 24.04 host kernel.

Repository/tooling used on the host:

```bash
cd ~
git clone -b main https://github.com/canonical/tdx.git
cd ~/tdx
sudo ./setup-tdx-host.sh
```

That setup installed the TDX-capable host stack and guest tooling under:

- `~/tdx/guest-tools/run_td`
- `~/tdx/guest-tools/image/create-td-image.sh`

## 4. Host TDX validation

After reboot, the host-side checks that mattered were:

```bash
sudo dmesg | grep -i tdx
cat /sys/module/kvm_intel/parameters/tdx
```

Expected host result:

- `virt/tdx: BIOS enabled: private KeyID range ...`
- `virt/tdx: module initialized`
- `/sys/module/kvm_intel/parameters/tdx` returns `Y`

At that point the host was a valid TDX host.

## 5. Host attestation stack

The direct TDX quote path also needed the host attestation components:

- `qgsd`
- `pccs`

The effective setup path was:

```bash
cd ~/tdx
sudo ./attestation/setup-attestation-host.sh
```

The important runtime checks were:

```bash
sudo systemctl enable --now qgsd
sudo systemctl status qgsd --no-pager

sudo systemctl status pccs --no-pager
sudo ~/tdx/attestation/check-registration.sh
```

At one point `check-registration.sh` reported:

- `platform not registered`

Later, after the host setup and registration path were completed, it reported:

- `mpa_manage: registration status OK.`

## 6. PCCS local configuration

`PCCS` was configured locally on the host with:

```bash
sudo /usr/bin/pccs-configure
```

The working choices for this machine were:

- accept local connections only: `Y`
- cache fill mode: `LAZY`
- generate insecure local HTTPS cert: `Y`
- local `admin` password: chosen locally
- local `user` password: chosen locally

Two different credentials matter here:

1. the local `PCCS` user password
2. the Intel PCS subscription key

They are not the same thing.

## 7. Intel PCS subscription key

The host originally failed here:

- `qgsd` logged `No certificate data for this platform`
- `pccs` logged `Intel PCS server returns error(401)`

The fix was to obtain a valid Intel PCS subscription key from the Intel Trusted Services portal and use the production key because the host was configured against the production PCS endpoint.

Portal:

- <https://api.portal.trustedservices.intel.com/>

The `PCCS` config file on this machine is:

- `/opt/intel/sgx-dcap-pccs/config/default.json`

The production PCS endpoint in that file is:

```json
"uri": "https://api.trustedservices.intel.com/sgx/certification/v4/"
```

So the `ApiKey` had to be a production PCS subscription key.

After obtaining the Intel PCS key, the flow was:

```bash
sudo systemctl restart pccs
sudo systemctl restart qgsd
```

## 8. Populate PCCS for this platform

Getting the Intel PCS key alone was not enough. The local `PCCS` also had to be populated for the current platform.

The working tool was:

```bash
sudo /usr/bin/PCKIDRetrievalTool \
  -url https://localhost:8081 \
  -user_token '<pccs_user_password_in_clear>' \
  -use_secure_cert false
```

Notes:

- `user_token` here is the local `PCCS` user password in clear text
- it is not the Intel PCS API key
- it is not the hash stored in `default.json`

After this step, the relevant `pccs` journal lines changed from:

- `401`
- `No cache data for this platform`

to successful API activity, including:

- `POST /sgx/certification/v4/platforms ... 200`
- `GET /sgx/certification/v4/pckcert ... 200`

And `qgsd` changed from:

- `tee_att_init_quote return 0x11001`

to:

- `tee_att_init_quote return success`
- `tee_att_get_quote_size return Success`
- `tee_att_get_quote return Success`

## 9. Guest creation and boot

Once the host was valid, the guest path used the Canonical guest tools:

```bash
cd ~/tdx/guest-tools/image
sudo ./create-td-image.sh -v 24.04
```

Then boot:

```bash
cd ~/tdx/guest-tools
./run_td --image ~/tdx/guest-tools/image/tdx-guest-ubuntu-24.04-generic.qcow2 --vcpus 16 --mem 16G
```

Inside the guest, the checks that mattered were:

```bash
ls -l /dev/tdx_guest
sudo dmesg | grep -i tdx
```

That confirmed the guest, not just the host, had TDX attestation available.

## 10. Repo-specific host-side runner

To avoid repeating the same host-to-guest steps manually, a repo-local runner was added:

- `tdx_tests/direct/run_host_tdx_guest_repo_tests.sh`

That script now handles:

- host TDX validation
- guest image creation/reuse
- guest boot
- guest dependency install
- guest install of `libboost-all-dev`, which is required if the repo-local ML-DSA path builds the local `QGS` direct-capability probe
- repo copy into the guest
- guest cleanup of stale build artifacts
- guest `ML-DSA` runs in `SIM`
- guest direct `ECDSA` run in `HW`
- host `qgsd` / `pccs` diagnostics on failure

## 11. Final functional state reached on this machine

After the host attestation stack and `PCCS` were fixed:

- direct `ECDSA` quote generation inside the TDX guest succeeded
- the guest direct flow printed:
  - real `TD REPORT`
  - successful `tdx_att_get_quote()`
  - full quote hex
  - verifier response `LOCAL_BINDING_ONLY`

The remaining distinction in the repo is deliberate:

- `ML-DSA` is still treated as the repo-local `SIM` path
- `ECDSA` is the real direct `TDX/HW` path

That split is reflected in the current host-side guest runner defaults.
