# signbridge (Python)

Thin client: spawns `signbridge-rpc` and speaks NDJSON. No native extension required.

```bash
cargo build -p signbridge-rpc
pip install -e bindings/python

python - <<'PY'
from signbridge import Client
with Client() as c:
    print(c.ping())
    for cert in c.list_certificates():
        print(cert["id"], cert["subject"])
PY
```

See [docs/PROTOCOL.md](../../docs/PROTOCOL.md).
