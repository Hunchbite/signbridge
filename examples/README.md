# Plug-and-play examples

Install the engine once, then run any example:

```bash
curl -fsSL https://raw.githubusercontent.com/Hunchbite/signbridge/main/scripts/install.sh | bash
export PATH="$HOME/.signbridge/bin:$PATH"
```

| Example | Command |
|---|---|
| Shell | `bash examples/shell/demo.sh` |
| Express | `cd examples/node-express && npm i && npm start` |
| FastAPI | `cd examples/python-fastapi && pip install -e ../../bindings/python fastapi uvicorn && uvicorn main:app --port 3848` |
| Node one-liner | build TS client, then `node examples/node-script/sign.mjs` |

All of them speak the same JSON protocol — swap SoftHSM for a real DSC token without changing app code.
