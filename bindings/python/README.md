# signbridge (Python) — plug and play

```bash
# once per machine
curl -fsSL https://raw.githubusercontent.com/Hunchbite/signbridge/main/scripts/install.sh | bash
export PATH="$HOME/.signbridge/bin:$PATH"

pip install -e .
```

```python
from signbridge import create

with create() as sb:   # finds engine on PATH or ~/.signbridge/bin (or installs it)
    print(sb.ping())
    for c in sb.list_certificates():
        print(c["id"], c["subject"])
```

See [docs/QUICKSTART.md](../../docs/QUICKSTART.md).
