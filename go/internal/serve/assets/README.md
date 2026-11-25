# Embedded demo assets (PRO-402)

`protodetect serve` runs no interpreter. These two files are embedded by `assets.go`:

- `demo.pcap`: the synthetic demo capture (`GET /api/sample` and the `demo` job). It holds locally built
  fixtures only, never real traffic. It was exported once from the Python reference's
  `presentation/server.py demo_bytes()` on 2026-11-25. The reference built a new one per request around a fresh
  OpenSSL ClientHello; the Go service always answers this one.
- `catalog.json`: the `protocols`, `applications` and `outcomes` tables of `catalog_data()`, in their order,
  exported from the reference on the same day. `assets.go` adds `source` (from `presentation/SOURCE.json`) and
  `limits`. While the reference exists, `make parity-server` compares `GET /api/catalog` byte for byte.

Export command (only while the Python reference is in the tree):

```bash
python3 -B -c "import sys,json; sys.path.insert(0,'presentation'); import server; open('go/internal/serve/assets/demo.pcap','wb').write(server.demo_bytes()); c=server.catalog_data(); del c['source'], c['limits']; open('go/internal/serve/assets/catalog.json','w').write(json.dumps(c, allow_nan=False)+'\n')"
```

The decryption showcase (`decrypt-demo`) is not an asset: `showcase.go` makes three TLS exchanges in memory with
Go's own TLS stack and a throwaway key, so no key or key log is committed.
