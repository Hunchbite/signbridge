"""SignBridge Python client — plug-and-play NDJSON over `signbridge-rpc`."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Optional

from .ensure import ensure_rpc, find_rpc

__all__ = [
    "Client",
    "SignBridgeError",
    "create",
    "ensure_rpc",
    "find_rpc",
]


class SignBridgeError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Client:
    """Spawn `signbridge-rpc` and exchange one JSON object per line."""

    def __init__(
        self,
        binary: Optional[str] = None,
        *,
        config: Optional[str | Path] = None,
        pin: Optional[str] = None,
        skip_origin: bool = True,
        auto_install: bool = True,
    ) -> None:
        if binary:
            self._bin = binary
        else:
            path = ensure_rpc(install=auto_install) if auto_install else find_rpc()
            if path is None:
                raise FileNotFoundError(
                    "signbridge-rpc not found. Run install.sh or pass binary=…"
                )
            self._bin = str(path)

        env = os.environ.copy()
        if config:
            env["SIGNBRIDGE_CONFIG"] = str(config)
        if pin:
            env["SIGNBRIDGE_PIN"] = pin
        if skip_origin:
            env["SIGNBRIDGE_SKIP_ORIGIN"] = "1"
        self._proc = subprocess.Popen(
            [self._bin],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            bufsize=1,
        )
        self._n = 0

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.stdin.close()
            self._proc.wait(timeout=5)

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def request(self, method: str, **payload: Any) -> Any:
        self._n += 1
        msg = {"id": str(self._n), "method": method, **payload}
        assert self._proc.stdin and self._proc.stdout
        self._proc.stdin.write(json.dumps(msg) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            err = self._proc.stderr.read() if self._proc.stderr else ""
            raise SignBridgeError("internal", f"rpc closed unexpectedly: {err}")
        data = json.loads(line)
        if not data.get("ok"):
            err = data.get("error") or {}
            raise SignBridgeError(err.get("code", "internal"), err.get("message", "unknown"))
        return data.get("result")

    def ping(self) -> dict:
        return self.request("ping")

    def list_certificates(self, origin: str = "cli://python") -> list:
        result = self.request("listCertificates", origin=origin)
        return result.get("certificates") or []

    def sign_hash(
        self,
        certificate_id: str,
        digest_hex: str,
        *,
        origin: str = "cli://python",
        hash_alg: str = "SHA-256",
        document_title: Optional[str] = None,
        document_id: Optional[str] = None,
    ) -> dict:
        params: dict[str, Any] = {
            "certificateId": certificate_id,
            "hashAlg": hash_alg,
            "digestHex": digest_hex,
        }
        if document_title:
            params["documentTitle"] = document_title
        if document_id:
            params["documentId"] = document_id
        return self.request("signHash", origin=origin, params=params)


def create(**kwargs: Any) -> Client:
    """Plug-and-play entry: ensure engine, return a ready Client."""
    return Client(**kwargs)
