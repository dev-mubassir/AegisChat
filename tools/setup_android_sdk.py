#!/usr/bin/env python3
"""Downloads and installs Android SDK command-line tools, platforms, and build-tools."""

import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request
import zipfile

SDK_ROOT = Path(r"C:\Users\mubas\AppData\Local\Android\Sdk")
JAVA_HOME = Path(r"C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot")
FLUTTER_CMD = r"C:\src\flutter\bin\flutter.bat"
CMDLINE_TOOLS_URL = (
    "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip"
)


def main():
    print(f"[*] Setting up Android SDK at: {SDK_ROOT}")
    os.environ["JAVA_HOME"] = str(JAVA_HOME)
    os.environ["PATH"] = f"{JAVA_HOME / 'bin'};{os.environ['PATH']}"

    latest_dir = SDK_ROOT / "cmdline-tools" / "latest"
    sdkmanager_bat = latest_dir / "bin" / "sdkmanager.bat"

    if not sdkmanager_bat.exists():
        print(f"[*] Downloading Android commandline tools from {CMDLINE_TOOLS_URL}...")
        with urllib.request.urlopen(CMDLINE_TOOLS_URL) as resp:
            data = resp.read()

        print("[*] Extracting command-line tools...")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            # cmdline-tools zip contains root folder `cmdline-tools/...`
            temp_extract = SDK_ROOT / "cmdline-tools" / "temp"
            zf.extractall(temp_extract)

        if latest_dir.exists():
            shutil.rmtree(latest_dir)
        (temp_extract / "cmdline-tools").rename(latest_dir)
        if temp_extract.exists():
            shutil.rmtree(temp_extract)
        print("[+] cmdline-tools extracted successfully.")
    else:
        print("[+] cmdline-tools already exists.")

    # Accept licenses
    print("[*] Accepting SDK licenses...")
    lic_proc = subprocess.Popen(
        [str(sdkmanager_bat), "--licenses", f"--sdk_root={SDK_ROOT}"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lic_proc.communicate(input="y\ny\ny\ny\ny\ny\ny\ny\ny\ny\ny\n")

    # Install packages: platform-tools, platforms;android-34, build-tools;34.0.0
    print("[*] Installing platform-tools, platforms;android-34, build-tools;34.0.0...")
    inst_proc = subprocess.run(
        [
            str(sdkmanager_bat),
            f"--sdk_root={SDK_ROOT}",
            "platform-tools",
            "platforms;android-34",
            "build-tools;34.0.0",
        ],
        input="y\n",
        text=True,
    )

    # Configure Flutter
    print("[*] Configuring Flutter Android SDK path...")
    subprocess.run([FLUTTER_CMD, "config", "--android-sdk", str(SDK_ROOT)], check=True)

    print("[*] Accepting Flutter Android licenses...")
    fl_lic = subprocess.Popen(
        [FLUTTER_CMD, "doctor", "--android-licenses"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    fl_lic.communicate(input="y\ny\ny\ny\ny\ny\ny\ny\ny\ny\ny\n")

    print("[+] Android SDK setup complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
