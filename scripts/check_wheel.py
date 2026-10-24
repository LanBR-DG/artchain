"""Install a wheel into a fresh environment and test away from the checkout."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import venv
import zipfile


def main():
    wheels = list(Path(sys.argv[1]).resolve().glob("artchain_provenance-*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Expected exactly one ArtChain wheel")
    wheel = wheels[0]
    with zipfile.ZipFile(wheel) as archive:
        required = {
            "artchain/crypto/bip39_english.txt", "artchain/web/index.html",
            "artchain/web/sw.js", "artchain/web/manifest.webmanifest",
            "artchain/web/icons/icon-192.png", "artchain/web/legal/privacy.html",
        }
        missing = required.difference(archive.namelist())
        if missing:
            raise SystemExit("Missing package resources: %s" % sorted(missing))
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("ARTCHAIN_DATA", None)
    env["PYTHONIOENCODING"] = "utf-8"
    with tempfile.TemporaryDirectory(prefix="artchain-wheel-") as directory:
        root = Path(directory)
        venv.EnvBuilder(with_pip=True).create(root / "venv")
        python = root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        def run(*args):
            subprocess.run([str(python), *args], cwd=root, env=env, check=True)
        run("-m", "pip", "install", "--no-index", "--no-deps", str(wheel))
        run("-m", "artchain", "--data", str(root / "data"), "selftest")
        print("PASS: installed wheel, resources, and self-tests outside source tree")


if __name__ == "__main__":
    main()
