"""Download the pinned workflow linter and verify bytes before executing it."""
import hashlib
import io
from pathlib import Path
import platform
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
VERSION = "1.7.12"
ASSETS = {
    "Linux": ("linux_amd64.tar.gz", "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8", "actionlint"),
    "Windows": ("windows_amd64.zip", "6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9", "actionlint.exe"),
}


def main():
    asset, digest, executable = ASSETS[platform.system()]
    cache = ROOT / ".cache/ci-tools" / VERSION
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / ("actionlint_" + VERSION + "_" + asset)
    if not archive.exists():
        url = "https://github.com/rhysd/actionlint/releases/download/v{}/{}".format(VERSION, archive.name)
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError("Actionlint download digest mismatch")
        archive.write_bytes(data)
    data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError("Actionlint cache digest mismatch")
    # Extract just the expected executable, never arbitrary archive paths.
    if asset.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            binary = bundle.read(executable)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as bundle:
            binary = bundle.extractfile(executable).read()
    tool = cache / executable
    tool.write_bytes(binary)
    tool.chmod(0o755)
    # Shell scripts have a separate ShellCheck job; disable host-dependent optional helpers.
    subprocess.run([str(tool), "-shellcheck=", "-pyflakes=", ".github/workflows/ci.yml",
                    ".github/workflows/dotnet.yml"], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
