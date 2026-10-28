"""Fetch fixed upstream source and verified tools; build the two real service variants."""

import hashlib
import json
import os
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / ".work"
LOCK = json.loads((ROOT / "config/upstream.json").read_text(encoding="utf-8"))


def run(*args, cwd=ROOT):
    subprocess.run(list(map(str, args)), cwd=cwd, check=True)


def java():
    home = os.environ.get("JAVA_HOME")
    executable = Path(home) / "bin" / ("java.exe" if os.name == "nt" else "java") if home else None
    found = executable if executable and executable.is_file() else shutil.which("java")
    if not found:
        raise RuntimeError("Install JDK 21 and set JAVA_HOME before preparing the lab")
    return str(found)


def archive(url, checksum, name, expected):
    WORK.mkdir(exist_ok=True)
    zipped_path = WORK / name
    if not zipped_path.exists():
        print(f"Downloading verified tool: {name}", flush=True)
        partial = zipped_path.with_suffix(".partial")
        urllib.request.urlretrieve(url, partial)
        partial.replace(zipped_path)
    with zipped_path.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != checksum:
            raise RuntimeError(f"Checksum mismatch: {name}")
    if not (WORK / expected).exists():
        with zipfile.ZipFile(zipped_path) as zipped:
            for item in zipped.infolist():
                if not (WORK / item.filename).resolve().is_relative_to(WORK.resolve()):
                    raise RuntimeError("Archive path escapes the work directory")
            zipped.extractall(WORK)
    return WORK / expected


def main():
    source = WORK / "crapi"
    if not source.exists():
        run("git", "clone", "--no-checkout", LOCK["repository"], source)
        run("git", "checkout", "--detach", LOCK["revision"], cwd=source)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if revision != LOCK["revision"]:
        raise RuntimeError("Upstream revision differs from the lock file")
    run("git", "diff", "--exit-code", cwd=source)
    gradle = archive(
        LOCK["gradle_url"], LOCK["gradle_sha256"], "gradle.zip", f"gradle-{LOCK['gradle_version']}"
    )
    archive(LOCK["zap_url"], LOCK["zap_sha256"], "zap.zip", f"ZAP_{LOCK['zap_version']}")
    for variant in ("vulnerable", "corrected"):
        target = WORK / variant
        if not target.exists():
            shutil.copytree(source / "services/identity", target)
            # The patch uses LF on every platform, including Windows checkouts.
            controller = target / "src/main/java/com/crapi/controller/VehicleController.java"
            controller.write_bytes(controller.read_bytes().replace(b"\r\n", b"\n"))
            if variant == "corrected":
                run(
                    "git",
                    "apply",
                    "--directory",
                    target.relative_to(ROOT),
                    "-p3",
                    ROOT / "patches/owner-check.patch",
                )
        if variant == "corrected":
            run(
                "git",
                "apply",
                "--reverse",
                "--check",
                "--directory",
                target.relative_to(ROOT),
                "-p3",
                ROOT / "patches/owner-check.patch",
            )
        print(f"Building pinned crAPI identity: {variant}", flush=True)
        run(
            java(),
            "-classpath",
            str(gradle / "lib/*"),
            "org.gradle.launcher.GradleMain",
            "--no-daemon",
            "--gradle-user-home",
            WORK / "gradle-home",
            "-p",
            target,
            "-Dorg.gradle.jvmargs=-Xmx768m",
            "bootJar",
        )
    print("Prepared real vulnerable and corrected crAPI identity service jars.")


if __name__ == "__main__":
    main()
