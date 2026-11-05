"""Locate or install `signbridge-rpc` for plug-and-play use."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO = os.environ.get("SIGNBRIDGE_REPO", "Hunchbite/signbridge")
HOME_BIN = Path(os.environ.get("SIGNBRIDGE_PREFIX", Path.home() / ".signbridge")) / "bin"


def _platform_asset() -> str:
    import platform

    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("arm64", "aarch64"):
        arch = "aarch64"
    else:
        raise RuntimeError(f"unsupported arch: {machine}")
    if system == "darwin":
        return f"signbridge-rpc-{arch}-apple-darwin"
    if system == "linux":
        return f"signbridge-rpc-{arch}-unknown-linux-gnu"
    if system == "windows":
        return f"signbridge-rpc-{arch}-pc-windows-msvc.exe"
    raise RuntimeError(f"unsupported OS: {system}")


def _candidates() -> list[Path]:
    out: list[Path] = []
    which = shutil.which("signbridge-rpc")
    if which:
        out.append(Path(which))
    out.append(HOME_BIN / "signbridge-rpc")
    # monorepo / editable install layouts
    here = Path(__file__).resolve()
    root = here.parents[3]  # repo root when editable
    out.append(root / "target" / "debug" / "signbridge-rpc")
    out.append(root / "target" / "release" / "signbridge-rpc")
    if env := os.environ.get("SIGNBRIDGE_RPC"):
        out.insert(0, Path(env))
    return out


def find_rpc() -> Path | None:
    for p in _candidates():
        if p.is_file() and os.access(p, os.X_OK):
            return p
    return None


def _download_release(dest: Path) -> bool:
    import json

    asset = _platform_asset()
    api = f"https://api.github.com/repos/{REPO}/releases/latest"
    try:
        with urllib.request.urlopen(api, timeout=30) as resp:
            data = json.load(resp)
    except Exception:
        return False
    url = None
    for a in data.get("assets") or []:
        if a.get("name") == asset or str(a.get("name", "")).startswith(asset.replace(".exe", "")):
            url = a.get("browser_download_url")
            break
    if not url:
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, dest)
    dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return True


def _cargo_install(dest_root: Path) -> Path:
    if not shutil.which("cargo"):
        raise FileNotFoundError(
            "signbridge-rpc not found and cargo is not installed. "
            "Run: curl -fsSL https://raw.githubusercontent.com/Hunchbite/signbridge/main/scripts/install.sh | bash"
        )
    subprocess.check_call(
        [
            "cargo",
            "install",
            "--git",
            f"https://github.com/{REPO}",
            "signbridge-rpc",
            "--root",
            str(dest_root.parent),  # ~/.signbridge
            "--force",
        ],
        stdout=sys.stderr,
    )
    bin_path = dest_root / "signbridge-rpc"
    if not bin_path.exists():
        raise FileNotFoundError("cargo install finished but binary missing")
    return bin_path


def ensure_rpc(*, install: bool = True) -> Path:
    """Return path to signbridge-rpc, optionally installing it."""
    found = find_rpc()
    if found:
        return found
    if not install:
        raise FileNotFoundError("signbridge-rpc not found")
    HOME_BIN.mkdir(parents=True, exist_ok=True)
    dest = HOME_BIN / "signbridge-rpc"
    if _download_release(dest):
        return dest
    return _cargo_install(HOME_BIN)
