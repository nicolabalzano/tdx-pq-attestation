## Test didattici per capire `tdx-guest` e `tee.dcap`

Questi test non richiedono un ambiente TDX attivo.

Servono a:
- seguire il flusso `TDREPORT -> TDVMCALL<GetQuote>`
- individuare dove `tee.dcap` trasforma il report in quote
- mostrare dove oggi il path TDX e' hardcoded su ECDSA

### Esecuzione

```bash
python3 -m unittest discover -s test -p 'test_*.py' -v
```

Oppure:

```bash
python3 test/run_tests.py
```

### Struttura

- `test/guest`: test sul crate `confidential-computing.tdx.tdx-guest`
- `test/dcap`: test sul repository `confidential-computing.tee.dcap`

### Limiti

Questi test sono statici: leggono i sorgenti e verificano che il flusso e i punti chiave
del codice siano quelli attesi. Sono pensati per orientarti prima di passare a test
end-to-end con un vero ambiente TDX/DCAP.
