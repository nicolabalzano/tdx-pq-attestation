# Directory Tree Of Modified Areas

Questo file riassume, per directory, le aree del tree in cui sono stati modificati o aggiunti file durante il lavoro su:

- path TDX-only trusted ML-DSA
- integrazione `SIM` per TDQE/QGS/wrapper
- test e probe ML-DSA
- supporto verifier/QVL ML-DSA

Nota:
- il tree sotto e' intenzionalmente riassuntivo
- sono evidenziate soprattutto le directory sorgente e test
- log, binari temporanei e altri artefatti generati non sono il focus principale

## Tree sintetico

```text
docs/
├── changes_from_start.md
├── next_step_mldsa_verifier.md
├── todo
└── modified_tree_summary.md

tdx_tests/
├── direct/
│   ├── run_mldsa_tdx_only_tests.sh
│   └── test_tdx_direct_mldsa_probe.cpp
├── tdqe/
│   └── test_tdqe_sim_loader.cpp
├── verifier/
│   └── test_tdx_mldsa_quote_verify_probe.cpp
└── wrapper/
    └── test_tdx_mldsa_init_quote_probe.cpp

confidential-computing.tee.dcap-pq/
├── QuoteGeneration/
│   ├── pce_wrapper/
│   │   └── linux/
│   │       └── Makefile
│   └── quote_wrapper/
│       ├── qgs/
│       │   ├── Makefile
│       │   └── qgs_ql_logic.cpp
│       └── tdx_quote/
│           ├── linux/
│           │   └── Makefile
│           ├── td_ql_logic.cpp
│           └── td_ql_wrapper.cpp
├── QuoteVerification/
│   ├── QVL/
│   │   └── Src/
│   │       └── AttestationLibrary/
│   │           └── src/
│   │               ├── QuoteVerification.cpp
│   │               ├── QuoteVerification/
│   │               │   ├── Quote.cpp
│   │               │   ├── Quote.h
│   │               │   ├── QuoteConstants.h
│   │               │   ├── QuoteStructures.cpp
│   │               │   └── QuoteStructures.h
│   │               └── Verifiers/
│   │                   └── QuoteVerifier.cpp
│   └── dcap_quoteverify/
│       ├── linux/
│       │   └── Makefile
│       └── sgx_dcap_quoteverify.cpp
└── ae/
    ├── QvE/
    │   └── qve/
    │       └── qve.cpp
    ├── dep/
    │   └── buildenv.mk
    ├── id_enclave/
    │   └── linux/
    │       └── Makefile
    └── tdqe/
        ├── linux/
        │   └── Makefile
        ├── quoting_enclave_tdqe.cpp
        └── tdqe.edl
```

## Riassunto per area

### `docs/`

Modificato o aggiunto:
- documentazione progressiva del lavoro
- stato dei test
- prossimo passo lato verifier

In pratica:
- `changes_from_start.md` tiene traccia dei fix e dei risultati raggiunti
- `todo` e' stato aggiornato con lo stato reale di generation e verifier
- `next_step_mldsa_verifier.md` descrive il blocker residuo e il prossimo passo corretto

### `tdx_tests/direct/`

Modificato o aggiunto:
- runner principale ML-DSA TDX-only
- probe diretto del path ML-DSA

In pratica:
- il runner ora copre build, probe e classificazione dei risultati
- il probe diretto verifica che il quote generato esponga davvero:
  - attestation key ML-DSA
  - `att_key_type = 5`
  - quote ML-DSA reale nel path repo-local `SIM`

### `tdx_tests/tdqe/`

Aggiunto:
- probe minimale per verificare il caricamento del TDQE in `SGX_MODE=SIM`

In pratica:
- serve a separare problemi di loader/runtime da problemi della logica ML-DSA

### `tdx_tests/wrapper/`

Aggiunto:
- probe minimale per `tee_att_create_context(...)`
- probe minimale per `tee_att_init_quote(...)`

In pratica:
- questi test sono serviti per localizzare i blocchi nel bootstrap trusted TDX-only ML-DSA

### `tdx_tests/verifier/`

Aggiunto:
- probe di verifica del quote ML-DSA

In pratica:
- genera un quote ML-DSA
- prova `tee_qv_get_collateral(...)`
- prova `tdx_qv_verify_quote(...)`
- distingue tra:
  - supporto reale
  - formato/certification data non supportati
  - limiti di collateral/runtime

### `QuoteGeneration/pce_wrapper/linux/`

Modificato:
- build/link in `SIM`

In pratica:
- allineamento del path `SIM` per evitare mismatch tra librerie `HW` e `SIM`

### `QuoteGeneration/quote_wrapper/qgs/`

Modificato:
- selezione corretta del context ML-DSA
- bootstrap sul context selezionato
- fix di cleanup/context switch
- supporto a `QGS_TDQE_PATH`
- build `SIM`

In pratica:
- il `QGS` locale ora riceve e usa davvero l’`att_key_id` ML-DSA
- non fa piu' bootstrap anticipato sul context di default

### `QuoteGeneration/quote_wrapper/tdx_quote/`

Modificato:
- bootstrap mode split:
  - `legacy_pce`
  - `trusted_tdx_only`
- implementazione del path trusted TDX-only ML-DSA
- generazione/uso del blob ML-DSA locale trusted
- quote generation ML-DSA
- fallback certification-data locale quando la platform collateral API non e' disponibile o fallisce
- derivazione automatica del path `ID_ENCLAVE`

In pratica:
- e' la parte centrale del lavoro lato generation
- da qui arriva il quote ML-DSA reale nel path repo-local `SIM`

### `QuoteVerification/QVL/.../QuoteVerification/`

Modificato:
- parser e strutture del quote per ML-DSA
- costanti di size ML-DSA
- supporto auth-data v4 ML-DSA

In pratica:
- il verifier non rifiuta piu' il quote ML-DSA a livello di parse/validate

### `QuoteVerification/QVL/.../Verifiers/`

Modificato:
- verifica della signature area ML-DSA

In pratica:
- `QuoteVerifier.cpp` ora usa `tdqe_mldsa65_verify(...)` per la signature del quote ML-DSA
- il path ECDSA esistente resta invariato

### `QuoteVerification/dcap_quoteverify/`

Modificato:
- build integration delle parti ML-DSA
- marker di debug nel path `tee_qv_get_collateral(...)`

In pratica:
- il verifier runtime include ora il supporto ML-DSA introdotto nel QVL

### `ae/QvE/qve/`

Modificato:
- marker per localizzare il comportamento di `tee_qv_get_collateral(...)`
- osservazione del punto in cui il verifier rifiuta la certification data

In pratica:
- ha permesso di dimostrare che il problema residuo non e' il parse del quote ML-DSA
- il problema residuo e' il tipo di certification data del quote locale

### `ae/dep/`

Modificato:
- build environment `SIM`

In pratica:
- supporto reale alle librerie SGX simulation nel path TDQE/QGS

### `ae/id_enclave/linux/`

Modificato:
- build `SIM`
- correzioni di link path e naming versionato

In pratica:
- l’`ID_ENCLAVE` puo' essere caricato nel path locale `SIM`

### `ae/tdqe/`

Modificato:
- build `SIM`
- supporto EDL per debug/ocall
- implementazione e debug del path ML-DSA nel TDQE
- fix nel blob path ML-DSA

In pratica:
- qui e' stata resa funzionante la generazione trusted della chiave e del quote ML-DSA
- i blocchi su `sgx_verify_report2(...)` in `SIM` sono stati isolati e bypassati solo nel path di test `SE_SIM`

## Conclusione sintetica

La modifica piu' importante ottenuta finora e' questa:

- il repo-local path `SIM` genera davvero quote TDX ML-DSA
- il verifier riesce a parse/validate quel quote
- il blocker residuo non e' piu' il formato del quote
- il blocker residuo e' la certification data attuale del quote locale, che il verifier classifica come non supportata

Il prossimo passo corretto e':

- far emettere al path ML-DSA una certification data verifier-compatible, preferibilmente `PCK_CERT_CHAIN`
