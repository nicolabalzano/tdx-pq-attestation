# Scopo Del Progetto, Motivazioni, Rischi Iniziali E Stato Di Risoluzione

## Scopo del progetto

Lo scopo di questo lavoro e' introdurre il supporto ML-DSA nel path di attestation TDX del repository, mantenendo invariato il trust boundary del sistema.

In pratica significa:

- aggiungere un nuovo algoritmo di attestation key (`MLDSA_65`)
- permettere al wrapper TDX di selezionarlo e propagarlo fino al backend trusted
- far generare il quote ML-DSA dal `TDQE`, non da codice userspace non trusted
- estendere il parser e il verifier lato `QVL/QV` in modo che il nuovo formato del quote sia compreso correttamente
- aggiungere test e probe repo-local che permettano di validare il flow anche in `SGX_MODE=SIM`

Il target non era "simulare una firma ML-DSA fuori dal TEE", ma far vivere il nuovo algoritmo dentro la pipeline di quote generation esistente, rispettando il modello di sicurezza del progetto.

## Perche' non era stato ancora fatto

Il lavoro non era ancora stato fatto per motivi tecnici e architetturali concreti:

- il formato quote Intel esistente era centrato su ECDSA, quindi mancavano:
  - nuovo `att_key_type`
  - nuovi layout `signature_data`
  - costanti e size ML-DSA
- il wrapper TDX e il path `tee_att_*` assumevano il flow storico ECDSA
- il `TDQE` non aveva un ramo ML-DSA per:
  - generazione chiave
  - sealing del blob
  - signing del quote
  - layout finale della signature area
- il verifier `QVL/QV` non aveva supporto strutturale completo per quote v4 ML-DSA
- il path standard di collateral/verifica DCAP dipende da certification data e servizi che non erano pronti per questo scenario locale
- il testing pratico era complicato dal fatto che il lavoro doveva partire senza una macchina reale SGX+TDX disponibile

Quindi il blocco non era solo "manca l'algoritmo". Mancava l'integrazione end-to-end tra:

- format
- wrapper
- trusted generation
- persistent key state
- parser/verifier
- test harness

## Problemi previsti prima di iniziare

Prima di iniziare, i problemi prevedibili erano questi.

### 1. Rischio di rompere il trust boundary

Rischio previsto:
- spostare la firma fuori dal `TDQE`
- gestire la private key ML-DSA in chiaro fuori dall'enclave

Perche' era importante:
- avrebbe reso il risultato inutilizzabile dal punto di vista di sicurezza

Stato:
- risolto

Come:
- la private key ML-DSA viene generata dentro `TDQE`
- viene conservata solo nel blob sealed
- la firma del quote avviene sempre nel `TDQE`
- il local verifier introdotto dopo e' stato limitato al solo contesto `SIM`, non al path standard reale

### 2. Rischio di non riuscire a introdurre ML-DSA senza rifare troppo codice

Rischio previsto:
- il codice esistente poteva essere troppo ECDSA-specifico
- la modifica poteva richiedere refactor troppo invasivi

Stato:
- sostanzialmente risolto

Come:
- e' stato introdotto il dispatch per algoritmo
- e' stato separato il path `legacy_pce` dal path `trusted_tdx_only`
- il supporto ML-DSA e' stato aggiunto accanto al path ECDSA, non al posto suo

### 3. Rischio di non riuscire a generare quote ML-DSA trusted in assenza di bootstrap legacy funzionante

Rischio previsto:
- il flow storico dipende da componenti legacy SGX/PCE/PSW
- senza una macchina completa, il bootstrap poteva fermarsi molto presto

Stato:
- risolto per il path repo-local di test

Come:
- e' stato introdotto un path `trusted_tdx_only`
- il bootstrap locale non dipende dal vecchio flow PCE-based
- questo ha permesso di arrivare alla generazione reale del quote ML-DSA in `SIM`

### 4. Rischio di collisioni o corruzione del persistent state tra ECDSA e ML-DSA

Rischio previsto:
- usare blob/state condivisi tra algoritmi diversi

Stato:
- risolto a livello di design e path principale

Come:
- il path ML-DSA usa una label blob separata:
  - `tdqe_data_mldsa_65.blob`
- ECDSA e ML-DSA hanno layout e gestione distinti

Nota:
- restano comunque utili test aggiuntivi di coesistenza e corruzione blob

### 5. Rischio che il parser/verifier rifiutasse subito il nuovo quote format

Rischio previsto:
- anche con generation funzionante, il verifier poteva fallire subito sul parse del quote

Stato:
- risolto

Come:
- `QVL` e `QuoteVerifier` sono stati estesi
- sono stati aggiunti unit test sul layout ML-DSA v4
- oggi il verifier standard parse/validate il quote ML-DSA strutturalmente

### 6. Rischio che il verifier non riuscisse a chiudere l'end-to-end nel setup locale

Rischio previsto:
- anche con parser ok, il path standard DCAP poteva fermarsi su collateral/certification data

Stato:
- confermato
- non ancora risolto nel path standard completo

Come si e' gestito:
- e' stata aggiunta diagnostica su `QPL/QCNL/PCCS`
- si e' verificato che il blocco non e' il formato del quote
- il blocco reale e' la certification data/collateral standard nel setup locale
- per `SIM` e' stato aggiunto un local verifier ML-DSA che verifica il quote in modo coerente, ma solo come fallback di test

Quindi:
- problema standard end-to-end: ancora aperto
- problema di test locale repo-controlled: risolto

### 7. Rischio che il debug diventasse ingestibile

Rischio previsto:
- per portare in piedi il flow sarebbe servita molta strumentazione
- i log potevano diventare troppo rumorosi e poco leggibili

Stato:
- risolto

Come:
- i debug dettagliati sono stati usati per localizzare i blocchi
- poi sono stati ridotti e resi opt-in tramite:
  - `TDX_MLDSA_VERBOSE_DEBUG=1`

### 8. Rischio di comportamenti non sicuri o troppo permissivi fuori da `SIM`

Rischio previsto:
- fallback locali e bypass di test potevano "sfuggire" nel path reale

Stato:
- risolto per quanto implementato finora

Come:
- i bypass `SE_SIM` restano confinati alla simulazione
- il local verifier viene eseguito solo in `SGX_MODE=SIM`
- il fallback collegato a `PLATFORM_UNKNOWN` e' esplicito e limitato al runner locale

## Cosa e' stato effettivamente ottenuto

Ad oggi il progetto ha ottenuto questi risultati concreti:

- il repository genera davvero quote TDX ML-DSA nel path repo-local `SIM`
- il direct probe mostra:
  - `att_key_type = 5`
  - `quote_size = 7102`
- il parser/verifier standard comprende il formato ML-DSA del quote
- il verifier standard non si ferma piu' sul parse, ma piu' avanti
- nel setup locale `SIM`, quando il collateral standard non e' disponibile, il local verifier ML-DSA chiude comunque la verifica del quote
- tutto questo e' stato fatto senza spostare la private key fuori dal `TDQE`

## Cosa non e' ancora completamente chiuso

Il punto ancora aperto non e' piu' il core ML-DSA.

Il punto aperto e' questo:

- validare il path standard completo di collateral/verifica DCAP su piattaforma reale SGX+TDX con certification data verifier-compatible

In altre parole:

- generation trusted locale: fatta
- verifier locale `SIM`: fatto
- parser/verifier standard lato formato: fatto
- standard DCAP end-to-end su macchina reale: ancora da provare

## Sintesi finale

Il motivo per cui questo lavoro non era gia' presente era che richiedeva un'integrazione trasversale tra:

- formato quote
- wrapper TDX
- trusted generation nel `TDQE`
- key state sealing
- verifier/QVL
- harness di test

I rischi principali erano:

- rompere il trust boundary
- dipendere troppo dal path legacy
- non riuscire a testare nulla senza hardware reale
- restare bloccati sul verifier

Lo stato attuale e' buono:

- i problemi di generation e integrazione trusted sono stati risolti
- il parser/verifier lato formato e' stato risolto
- il problema residuo e' limitato al path standard collateral/verifier completo, che richiede una validazione su piattaforma reale o collateral standard compatibile
