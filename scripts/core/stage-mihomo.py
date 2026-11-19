#!/usr/bin/env python3
"""Build the checked-out Mihomo submodule and stage its isolated executable."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "core/mihomo"
TARGETS = {
    "linux-x64": ("linux", "amd64", None),
    "windows-x64": ("windows", "amd64", None),
    "macos-x64": ("darwin", "amd64", None),
    "macos-arm64": ("darwin", "arm64", None),
    "android-arm64-v8a": ("android", "arm64", "aarch64-linux-android"),
    "android-armeabi-v7a": ("android", "arm", "armv7a-linux-androideabi"),
    "android-x86_64": ("android", "amd64", "x86_64-linux-android"),
}


def git(*args):
    return subprocess.check_output(["git", "-C", str(SOURCE), *args], text=True).strip()


def android_compiler(triple):
    ndk = next((os.environ[key] for key in
                ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "FCAE_NDK_PATH", "NDK_HOME")
                if os.environ.get(key)), None)
    if not ndk:
        raise RuntimeError("set ANDROID_NDK_HOME to build Mihomo for Android")
    host = {"Linux": "linux-x86_64", "Darwin": "darwin-x86_64", "Windows": "windows-x86_64"}[platform.system()]
    suffix = ".cmd" if os.name == "nt" else ""
    compiler = Path(ndk) / "toolchains/llvm/prebuilt" / host / "bin" / (triple + "23-clang" + suffix)
    if not compiler.is_file():
        raise RuntimeError(f"Android NDK compiler missing: {compiler}")
    return str(compiler)


def stage(target, version, timestamp):
    goos, goarch, triple = TARGETS[target]
    if goos == "android":
        destination = ROOT / "android/app/src/main/jniLibs" / target[len("android-"):] / "libmihomo_exec.so"
    else:
        destination = ROOT / "build" / ("mihomo.exe" if goos == "windows" else "mihomo")
    destination.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    # Do not inherit another core's cross-compilation or shared-library settings.
    env.update(GOOS=goos, GOARCH=goarch, GOAMD64="v1", GOARM="7", CGO_ENABLED="0", GOWORK="off")
    env.setdefault("GOTOOLCHAIN", "go1.26.11")
    if triple:
        env.update(CGO_ENABLED="1", CC=android_compiler(triple))
    flags = ("-s -w -buildid= "
             f"-X github.com/metacubex/mihomo/constant.Version={version} "
             f"-X github.com/metacubex/mihomo/constant.BuildTime={timestamp}")
    with tempfile.TemporaryDirectory(prefix="mihomo-build-", dir=destination.parent) as temporary:
        output = Path(temporary) / destination.name
        command = ["go", "build", "-mod=readonly", "-buildvcs=false", "-trimpath",
                   "-tags", "with_gvisor", "-ldflags", flags]
        if triple:
            command += ["-buildmode=pie"]
        command += ["-o", str(output), "."]
        subprocess.run(command, cwd=SOURCE, env=env, check=True)
        output.chmod(0o755)
        os.replace(output, destination)
    print(destination)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in (*TARGETS, "android-universal"):
        raise RuntimeError("expected a desktop/Android build matrix target")
    if not (SOURCE / "go.mod").is_file() or not (SOURCE / "main.go").is_file():
        raise RuntimeError("initialize Mihomo first: git submodule update --init --recursive core/mihomo")
    revision = git("rev-parse", "HEAD")
    version = git("describe", "--tags", "--always")
    timestamp = git("show", "-s", "--format=%cI", "HEAD")
    targets = ("android-arm64-v8a", "android-armeabi-v7a", "android-x86_64") if sys.argv[1] == "android-universal" else (sys.argv[1],)
    for target in targets:
        stage(target, version, timestamp)
    metadata = ROOT / "build/mihomo-source.json"
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text(json.dumps({"source": "https://github.com/MetaCubeX/mihomo.git",
                                    "commit": revision, "version": version}, indent=2) + "\n")


if __name__ == "__main__":
    main()
