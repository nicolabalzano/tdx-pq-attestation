# Modifiche Effettuate Dall'Inizio

Questo file documenta in modo puntuale tutte le modifiche fatte finora nel repository e nel submodule `confidential-computing.tee.dcap-pq`, con riferimenti ai file e con estratti del codice corrente.

## 1. Schema del nuovo algoritmo nel formato quote

### File: `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h`

Ho introdotto il nuovo `algorithm_id` ML-DSA e il nuovo layout `signature_data` per quote v3.

Riferimenti:
- `SGX_QL_ALG_MLDSA_65` e nuovi size constant: righe 48-59
- nuovo struct `sgx_ql_mldsa_65_sig_data_t`: righe 168-183

Estratto:

```c
typedef enum {
    SGX_QL_ALG_EPID = 0,
    SGX_QL_ALG_RESERVED_1 = 1,
    SGX_QL_ALG_ECDSA_P256 = 2,
    SGX_QL_ALG_ECDSA_P384 = 3,
    SGX_QL_ALG_MLDSA_65 = 5,
    SGX_QL_ALG_MAX = 6,
} sgx_ql_attestation_algorithm_id_t;

#define SGX_QL_MLDSA_65_SIG_SIZE 3309
#define SGX_QL_MLDSA_65_PUB_KEY_SIZE 1952
```

```c
typedef struct _sgx_ql_mldsa_65_sig_data_t {
    uint8_t               sig[SGX_QL_MLDSA_65_SIG_SIZE];
    uint8_t               attest_pub_key[SGX_QL_MLDSA_65_PUB_KEY_SIZE];
    sgx_report_body_t     qe_report;
    uint8_t               qe_report_sig[32*2];
    uint8_t               auth_certification_data[];
} sgx_ql_mldsa_65_sig_data_t;
```

Nota:
- il `report_body` del quote non e' stato cambiato
- la differenza e' stata isolata dentro `signature_data`

### File: `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h`

Ho introdotto il layout `signature_data` ML-DSA per quote v4.

Riferimenti:
- nuovo struct `sgx_mldsa_65_sig_data_v4_t`: righe 111-122

Estratto:

```c
typedef struct _sgx_mldsa_65_sig_data_v4_t {
     uint8_t             sig[SGX_QL_MLDSA_65_SIG_SIZE];
     uint8_t             attest_pub_key[SGX_QL_MLDSA_65_PUB_KEY_SIZE];
     uint8_t             certification_data[];
} sgx_mldsa_65_sig_data_v4_t;
```

## 2. Correzione del path degli header locali del quote

### File: `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/inc/td_ql_wrapper.h`

Ho corretto l'include per forzare l'uso dell'header `sgx_quote_4.h` del repository, evitando la collisione con l'header omonimo del SDK locale.

Riferimento:
- riga 41

Estratto:

```c
#include "../../common/inc/sgx_quote_4.h"
```

Perche' e' stato necessario:
- il test `g++ -H -fsyntax-only ... td_ql_wrapper.cpp` mostrava che il compilatore stava includendo `tdx_tests/sgxsdk/include/sgx_quote_4.h`
- quindi `SGX_QL_ALG_MLDSA_65` non era visibile nel wrapper, anche se era stato aggiunto nel file locale del repo

## 3. Generalizzazione del wrapper TDX per `MLDSA_65`

### File: `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_wrapper.cpp`

Ho generalizzato il wrapper per:
- accettare `SGX_QL_ALG_MLDSA_65` nel context
- restituire un `att_key_id` coerente col contesto
- delegare `init_quote`, `get_quote_size` e `get_quote` a un dispatch nel contesto

Riferimenti:
- nuovo default key id ML-DSA: righe 78-94
- whitelist algoritmi supportati: righe 96-112
- validazione contesto e salvataggio dell'algoritmo nel context: righe 115-159
- chiamata al dispatcher `init_quote(...)`: riga 226
- chiamata al dispatcher `get_quote_size(...)`: riga 327
- chiamata al dispatcher `get_quote(...)`: righe 413-414
- `tee_att_get_keyid(...)` coerente col contesto: righe 509-522

Estratti:

```c
extern const sgx_ql_att_key_id_t g_default_mldsa_65_att_key_id = { ... SGX_QL_ALG_MLDSA_65 };
```

```c
static bool is_supported_tdx_att_key_algorithm(uint32_t algorithm_id)
{
    return algorithm_id == SGX_QL_ALG_ECDSA_P256 ||
           algorithm_id == SGX_QL_ALG_MLDSA_65;
}
```

```c
p_context->m_att_key_algorithm_id = p_att_key_id ?
    static_cast<sgx_ql_attestation_algorithm_id_t>(p_att_key_id->base.algorithm_id)
    : SGX_QL_ALG_ECDSA_P256;
```

```c
ret_val = const_cast<tee_att_config_t*>(p_context)->init_quote(...);
ret_val = const_cast<tee_att_config_t*>(p_context)->get_quote_size(...);
ret_val = const_cast<tee_att_config_t*>(p_context)->get_quote(...);
```

```c
const sgx_ql_att_key_id_t* p_default_att_key_id =
    get_default_att_key_id_for_algorithm(p_context->m_att_key_algorithm_id);
```

## 4. Stato algoritmico nel contesto `tee_att_config_t`

### File: `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.h`

Ho aggiunto al contesto TDX il campo che memorizza l'algoritmo richiesto e ho definito un'interfaccia interna con dispatcher per algoritmo.

Riferimenti:
- nuovo campo `m_att_key_algorithm_id`: riga 85
- default costruttore a `SGX_QL_ALG_ECDSA_P256`: righe 90-98
- nuove API interne `mldsa_*` e dispatcher `init_quote/get_quote_size/get_quote`: righe 141-170
- include corretto dell'header locale `sgx_quote_5.h`: riga 41

Estratti:

```c
sgx_ql_attestation_algorithm_id_t m_att_key_algorithm_id;
```

```c
m_att_key_algorithm_id(SGX_QL_ALG_ECDSA_P256)
```

```c
tee_att_error_t mldsa_init_quote(...);
tee_att_error_t mldsa_get_quote_size(...);
tee_att_error_t mldsa_get_quote(...);

tee_att_error_t init_quote(...);
tee_att_error_t get_quote_size(...);
tee_att_error_t get_quote(...);
```

## 5. Dispatch interno per algoritmo in `td_ql_logic.cpp`

### File: `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

Ho trasformato il path interno in un dispatcher per algoritmo, lasciando il path ECDSA invariato e aggiungendo stub espliciti per ML-DSA che oggi restituiscono `TEE_ATT_UNSUPPORTED_ATT_KEY_ID`.

Riferimenti:
- dispatcher `init_quote(...)`: righe 1035-1049
- stub `mldsa_init_quote(...)`: righe 1571-1580
- dispatcher `get_quote_size(...)`: righe 1599-1611
- dispatcher `get_quote(...)`: righe 1833-1846
- stub `mldsa_get_quote(...)`: righe 2114-2121

Estratti:

```c
switch (m_att_key_algorithm_id)
{
case SGX_QL_ALG_ECDSA_P256:
    return ecdsa_init_quote(...);
case SGX_QL_ALG_MLDSA_65:
    return mldsa_init_quote(...);
default:
    return TEE_ATT_UNSUPPORTED_ATT_KEY_ID;
}
```

```c
tee_att_error_t tee_att_config_t::mldsa_init_quote(...)
{
    return TEE_ATT_UNSUPPORTED_ATT_KEY_ID;
}
```

```c
tee_att_error_t tee_att_config_t::mldsa_get_quote(...)
{
    return TEE_ATT_UNSUPPORTED_ATT_KEY_ID;
}
```

### Chiamate al TDQE aggiornate

Nello stesso file ho propagato `m_att_key_algorithm_id` fino alle ECALL del TDQE.

Riferimenti:
- `gen_att_key(...)`: call site con `algorithm_id` nel blocco intorno alle righe 1419-1426 del file corrente
- `gen_quote(...)`: righe 2041-2045

Estratto:

```c
sgx_status = gen_quote(m_eid,
                       (uint32_t*)&tdqe_error,
                       (uint8_t*)m_ecdsa_blob,
                       (uint32_t)sizeof(m_ecdsa_blob),
                       static_cast<uint32_t>(m_att_key_algorithm_id),
                       p_app_report,
                       ...);
```

Nota:
- il nome dei blob e la struttura blob sono ancora ECDSA-only
- non sono ancora stati separati blob/cache/label per ML-DSA

### Separazione dei blob persistenti per algoritmo

Successivamente, nello stesso file, ho separato il label del persistent storage per evitare che un contesto `MLDSA_65` riutilizzi o sovrascriva il file blob ECDSA.

Riferimenti:
- nuovi label e helper: righe 27-45
- write dopo `store_cert_data(...)`: righe 990-993
- read in `ecdsa_init_quote(...)`: righe 1151-1154
- write del blob resealed in `ecdsa_init_quote(...)`: righe 1204-1207
- read in `ecdsa_get_quote_size(...)`: righe 1669-1672
- write del blob resealed in `ecdsa_get_quote_size(...)`: righe 1708-1710
- read in `ecdsa_get_quote(...)`: righe 1905-1908
- write del blob resealed in `ecdsa_get_quote(...)`: righe 1945-1947

Estratti:

```c
#define ECDSA_BLOB_LABEL "tdqe_data.blob"
#define MLDSA_65_BLOB_LABEL "tdqe_data_mldsa_65.blob"

static const char* get_blob_label_for_algorithm(uint32_t algorithm_id)
{
    switch (algorithm_id)
    {
    case SGX_QL_ALG_MLDSA_65:
        return MLDSA_65_BLOB_LABEL;
    case SGX_QL_ALG_ECDSA_P256:
    default:
        return ECDSA_BLOB_LABEL;
    }
}
```

```c
refqt_ret = read_persistent_data((uint8_t*)m_ecdsa_blob,
                                 &blob_size_read,
                                 get_blob_label_for_algorithm(m_att_key_algorithm_id));
```

```c
refqt_ret = write_persistent_data((uint8_t *)m_ecdsa_blob,
                                  sizeof(m_ecdsa_blob),
                                  get_blob_label_for_algorithm(m_att_key_algorithm_id));
```

Nota importante:
- il buffer in memoria si chiama ancora `m_ecdsa_blob`
- il formato del blob non e' ancora ML-DSA-native
- pero' a questo punto il file persistente usato da `MLDSA_65` e' distinto da quello ECDSA

## 6. Estensione delle ECALL del TDQE

### File: `confidential-computing.tee.dcap-pq/ae/tdqe/tdqe.edl`

Ho aggiunto `uint32_t algorithm_id` alle ECALL che devono sapere quale algoritmo si vuole usare:
- `gen_att_key(...)`
- `gen_quote(...)`

Riferimenti:
- `gen_att_key(...)`: righe 47-53
- `gen_quote(...)`: righe 69-79

Estratto:

```c
public uint32_t gen_att_key(...,
                            uint32_t algorithm_id,
                            ...);

public uint32_t gen_quote(...,
                          uint32_t algorithm_id,
                          ...);
```

## 7. Branch algoritmo nel TDQE

### File: `confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`

Ho portato il nuovo parametro `algorithm_id` dentro il TDQE e ho aggiunto il branch esplicito:
- ECDSA continua a usare il path esistente
- ogni algoritmo diverso da `SGX_QL_ALG_ECDSA_P256` viene per ora rifiutato con `TDQE_ERROR_INVALID_PARAMETER`

Riferimenti:
- `gen_att_key(...)` ora accetta `algorithm_id`: righe 775-781
- check esplicito in `gen_att_key(...)`: righe 820-822
- `gen_quote(...)` ora accetta `algorithm_id`: righe 1359-1369
- check esplicito in `gen_quote(...)`: righe 1435-1437

Estratti:

```c
uint32_t gen_att_key(uint8_t *p_blob,
    uint32_t blob_size,
    uint32_t algorithm_id,
    ...)
```

```c
if (algorithm_id != SGX_QL_ALG_ECDSA_P256) {
    return(TDQE_ERROR_INVALID_PARAMETER);
}
```

```c
uint32_t gen_quote(uint8_t *p_blob,
    uint32_t blob_size,
    uint32_t algorithm_id,
    ...)
```

```c
if (algorithm_id != SGX_QL_ALG_ECDSA_P256) {
    return(TDQE_ERROR_INVALID_PARAMETER);
}
```

Nota importante:
- il quote reale continua a essere firmato con ECDSA
- il punto dove questo e' ancora evidente e' il path che imposta:

```c
p_quote->header.att_key_type = SGX_QL_ALG_ECDSA_P256;
sgx_status = sgx_ecdsa_sign(...);
sgx_status = sgx_ecdsa_verify(...);
```

Questa parte non e' ancora stata convertita a ML-DSA.

## 8. Aggiornamento del file `todo`

### File: `todo`

Ho aggiornato il `todo` per riflettere:
- stato attuale del lavoro
- fasi e sottopassi effettivamente completati
- test realmente eseguiti
- blocco locale sui file `root:root` nella build completa del TDQE

Riferimenti:
- sezione `Stato attuale`: righe 16-26
- avanzamento Fase 2: righe 98-109
- avanzamento Fase 3: righe 111-136
- avanzamento Fase 4: righe 138-155

Estratto:

```md
- `td_ql_logic.*` ora ha un dispatch per algoritmo con stub `MLDSA_65`
- `algorithm_id` viene ora propagato dal wrapper fino alle ECALL `gen_att_key` e `gen_quote` del TDQE
- il TDQE ha ora un branch esplicito che lascia invariato ECDSA e rifiuta per ora `MLDSA_65`
```

## 9. Verifiche eseguite

### Verifiche andate a buon fine

1. `td_ql_wrapper.cpp`

Verifica sintattica riuscita:

```bash
g++ -std=c++14 -fsyntax-only ... td_ql_wrapper.cpp
```

2. Componente reale `tdx_quote/linux`

Build completa riuscita:

```bash
make -C confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

3. `quoting_enclave_tdqe.cpp`

Verifica sintattica riuscita:

```bash
g++ -std=c++14 -fsyntax-only ... quoting_enclave_tdqe.cpp
```

### Verifica bloccata dall'ambiente

Build completa del TDQE:

```bash
make -C confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Blocco riscontrato:

```text
Fatal error: exception Sys_error("./tdqe_t.h: Permission denied")
```

Causa osservata:
- `confidential-computing.tee.dcap-pq/ae/tdqe/linux/tdqe_t.c`
- `confidential-computing.tee.dcap-pq/ae/tdqe/linux/tdqe_t.h`

sono file `root:root`, quindi `sgx_edger8r` non puo' rigenerarli nel build locale corrente.

## 10. Stato funzionale finale dopo queste modifiche

Stato attuale del codice:
- il formato quote conosce `SGX_QL_ALG_MLDSA_65`
- il wrapper TDX puo' accettare un context ML-DSA
- `td_ql_logic` sa dispatchare per algoritmo
- il parametro algoritmo arriva fino al TDQE
- il TDQE oggi rifiuta ancora ML-DSA e mantiene invariato il path ECDSA
- il quote reale non e' ancora firmato con ML-DSA

Il prossimo passo necessario, per rispettare il `todo`, e':
- sostituire nel TDQE il branch di rifiuto con generazione chiave ML-DSA
- serializzazione della public key ML-DSA
- firma ML-DSA del buffer del quote
- verifica interna ML-DSA
- aggiornamento del verifier QVL/QvE per il nuovo `signature_data`
