## Rust lab per capire `tdx-guest` e `tee.dcap`

Questo mini progetto usa davvero il crate Rust [`tdx-guest`](../../confidential-computing.tdx.tdx-guest)
e aggiunge binari di studio.

### Cosa fa

- `guest_api_tour`
  Mostra le strutture e le API principali di `tdx-guest`.
- `dcap_source_tour`
  Legge i file chiave di `tee.dcap` e stampa il flusso reale del quote TDX.

### Comandi

```bash
cd test/rust_lab
cargo run --bin guest_source_tour
```

Questo binario compila su stable e ti guida nel modulo `tdx-guest` leggendo i file Rust reali.

```bash
cd test/rust_lab
cargo run --bin guest_api_tour --features guest
```

Questo invece usa davvero il crate `tdx-guest`, quindi nel tuo ambiente attuale puo'
richiedere un toolchain Rust nightly o comunque compatibile con le dipendenze del crate.

```bash
cd test/rust_lab
cargo run --bin dcap_source_tour
```

### Nota importante

`guest_api_tour` puo' compilare anche fuori da una TD, ma le chiamate TDX vere
(`get_report`, `extend_rtmr`, `get_quote`) vengono eseguite solo se il processo
sta girando davvero in un guest TDX.

Per compilare `guest_api_tour`:

```bash
cd test/rust_lab
cargo run --features guest --bin guest_api_tour
```

Se vedi errori da crate `x86_64` sul canale stable, usa invece:

```bash
cd test/rust_lab
cargo run --bin guest_source_tour
```

Fuori da TDX il programma stampa:
- le firme delle funzioni
- le dimensioni delle strutture
- i buffer che dovresti preparare
- perche' il quote vero non parte fuori dall'ambiente corretto
