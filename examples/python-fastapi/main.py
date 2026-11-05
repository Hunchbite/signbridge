"""
Plug-and-play FastAPI app using SignBridge.

  cargo build -p signbridge-rpc
  pip install -e ../../bindings/python fastapi uvicorn
  uvicorn main:app --port 3848

  curl -s localhost:3848/health
  curl -s localhost:3848/certs
  curl -s -X POST localhost:3848/sign -H 'content-type: application/json' \
    -d '{"text":"hello contract"}'
"""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from signbridge import Client, create


class SignBody(BaseModel):
    text: Optional[str] = None
    digest_hex: Optional[str] = None
    certificate_id: Optional[str] = None
    title: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.sb = create()
    yield
    app.state.sb.close()


app = FastAPI(title="SignBridge FastAPI example", lifespan=lifespan)


@app.get("/health")
def health():
    return {"ok": True, "engine": app.state.sb.ping()}


@app.get("/certs")
def certs():
    return {"certificates": app.state.sb.list_certificates()}


@app.post("/sign")
def sign(body: SignBody):
    if body.digest_hex:
        digest = body.digest_hex
    elif body.text is not None:
        digest = hashlib.sha256(body.text.encode()).hexdigest()
    else:
        raise HTTPException(400, "provide text or digest_hex")

    certs = app.state.sb.list_certificates()
    if not certs:
        raise HTTPException(503, "no certificates — plug in a DSC or SoftHSM")

    cert_id = body.certificate_id or certs[0]["id"]
    result = app.state.sb.sign_hash(
        cert_id,
        digest,
        document_title=body.title or "fastapi-demo",
    )
    return {"ok": True, "digestHex": digest, **result}
