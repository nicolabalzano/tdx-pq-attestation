#include <cstdint>
#include <cstdio>
#include <cstring>

#include "sgx_error.h"
#include "sgx_urts.h"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <signed-enclave-path>\n", argv[0]);
        return 2;
    }

    const char* enclave_path = argv[1];
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_misc_attribute_t misc = {};

    std::fprintf(stderr, "[test] loading enclave: %s\n", enclave_path);
    const sgx_status_t status =
        sgx_create_enclave(enclave_path, 0, &token, &updated, &eid, &misc);
    std::fprintf(stderr, "[test] sgx_create_enclave returned: 0x%04x\n", status);

    if (status == SGX_SUCCESS && eid != 0) {
        sgx_destroy_enclave(eid);
        std::fprintf(stderr, "[test] enclave load/unload completed\n");
        return 0;
    }
    return 1;
}
