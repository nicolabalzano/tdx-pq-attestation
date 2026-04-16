Ricevuto. Ecco l'elenco espanso ma mantenuto in uno stile **minimale e tecnico**, ottimizzato per i tuoi benchmark:

---

### 1. Success versus failure
* **Success Rate:** Percentuale di completamento su un set di $N$ tentativi.
* **Failure Analysis:** Tracciamento dei motivi di errore:
    * *Timeout:* Dovuti al numero eccessivo di iterazioni di firma.
    * *Memory Failure:* Errori di allocazione per buffer PQC insufficienti.
    * *Collateral Failure:* Errori nel recupero dei certificati PQC-ready.

### 2. ECDSA quote size versus ML-DSA quote size
* **Total Byte Count:** Dimensione totale del pacchetto di attestazione.
* **Signature Breakdown:** Byte della sola firma crittografica (es. 64B vs 2.4KB+).
* **Certification Data Overhead:** Dimensione dei certificati della Quoting Enclave (QE).
* **Network Fragmentation:** Numero di segmenti TCP necessari (impatto dell'MTU).



### 3. ECDSA execution cost versus ML-DSA execution cost
* **Context creation:** Latenza di inizializzazione delle librerie crittografiche e caricamento parametri.
* **Init_quote:** Tempo per recuperare Target Info e caricare la Quoting Enclave (QE).
* **Quote-size retrieval:** Overhead per calcolare dinamicamente la dimensione dei buffer PQC variabili.
* **Quote generation:** * *Wall-clock time:* Tempo totale di generazione.
    * *CPU Cycles:* Cicli macchina consumati (istruzioni eseguite).
    * *Loop Count:* Numero di tentativi di *rejection sampling* (solo per ML-DSA).
* **Quote verification:** Latenza per validare la firma e la catena di certificati (root-of-trust).
* **Full end-to-end flow:** Tempo totale dalla richiesta nel Guest TDX alla risposta del Verifier.



### 4. ECDSA verification behavior versus ML-DSA verification behavior
* **Scalability:** Tempo di verifica all'aumentare delle richieste parallele (throughput).
* **Cache Impact:** Differenza di latenza tra verifica "warm" (certificati in cache) e "cold" (recupero PCCS).yy
* **Computational Intensity:** Utilizzo di memoria RAM (stack/heap) durante l'operazione di verifica.

---

**Consiglio per i log:** Per la voce **Quote Generation**, assicurati di loggare separatamente il tempo speso "dentro" la Quoting Enclave rispetto al tempo di trasporto, altrimenti la latenza di ML-DSA sembrerà più alta solo a causa dello spostamento di più byte.