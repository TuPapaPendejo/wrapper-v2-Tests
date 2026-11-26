#!/usr/bin/env python3
"""Stage a new rootfs from the user's APK/APKM and pinned Android system files."""

import argparse
import hashlib
import io
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from architecture import load_profile, verify_elf


ROOT = Path(__file__).resolve().parents[1]
PINS = load_profile()
MAX_APK_ENTRY_SIZE = 128 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def profile_metadata(pins, certificate):
    """Record the CA bundle identity without embedding certificate contents."""
    keys = ("architecture", "profile", "context_profile", "context_supported")
    metadata = {key: pins[key] for key in keys}
    metadata["ca_bundle_sha256"] = digest(certificate)
    return metadata


def extract_apple(source, pins=None):
    pins = pins or PINS
    split_name = pins["apk_split"]
    split_in_bundle = False

    with zipfile.ZipFile(source) as outer:
        if split_name in outer.namelist():
            split_in_bundle = True
            if "base.apk" not in outer.namelist():
                raise ValueError("missing or oversized base APK")
            base_info = outer.getinfo("base.apk")
            if base_info.file_size > MAX_APK_ENTRY_SIZE:
                raise ValueError("missing or oversized base APK")

            with zipfile.ZipFile(io.BytesIO(outer.read(base_info))) as base:
                base_manifest = base.read("AndroidManifest.xml")
            if digest(base_manifest) != pins["base_manifest_sha256"]:
                raise ValueError("unsupported APK build")

            split_info = outer.getinfo(split_name)
            if split_info.file_size > MAX_APK_ENTRY_SIZE:
                raise ValueError("oversized APK split")
            archive = zipfile.ZipFile(io.BytesIO(outer.read(split_info)))
        else:
            archive = outer

        try:
            expected_manifests = {pins["split_manifest_sha256"]}
            if not split_in_bundle:
                expected_manifests.add(pins["base_manifest_sha256"])

            if "AndroidManifest.xml" not in archive.namelist():
                raise ValueError("unsupported APK architecture/build")
            manifest = archive.read("AndroidManifest.xml")
            if digest(manifest) not in expected_manifests:
                raise ValueError("unsupported APK architecture/build")

            files = {}
            architecture = pins["architecture"]
            for name, expected_hash in pins["apple_libraries"].items():
                library_path = f"lib/{architecture}/{name}"
                matches = [
                    entry for entry in archive.infolist()
                    if entry.filename == library_path
                ]
                if len(matches) != 1 or matches[0].file_size > MAX_APK_ENTRY_SIZE:
                    raise ValueError("missing or ambiguous pinned library: " + name)

                data = archive.read(matches[0])
                if digest(data) != expected_hash:
                    raise ValueError("unsupported Apple library: " + name)
                verify_elf(data, pins)
                files[name] = data

            return files
        finally:
            if archive is not outer:
                archive.close()


def stage(apk, system, worker, output, ca, pins=None):
    pins = pins or PINS
    output = output.absolute()
    if output.exists():
        raise ValueError("output must not exist")

    # Verify every source before creating the rootfs. Only allowlisted paths
    # are copied into the generated filesystem.
    apple = extract_apple(apk, pins)
    android = {}

    for relative_path, expected_hash in pins["android_system"].items():
        source = system / relative_path
        if source.is_symlink() or not source.is_file():
            raise ValueError("missing Android artifact: " + relative_path)

        data = source.read_bytes()
        if digest(data) != expected_hash:
            raise ValueError("unsupported Android artifact: " + relative_path)
        if relative_path.startswith(("bin/", "lib64/")):
            verify_elf(data, pins)
        android[relative_path] = data

    worker_data = worker.read_bytes()
    verify_elf(worker_data, pins)

    certificate_bundle = ca.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" not in certificate_bundle:
        raise ValueError("invalid CA bundle")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_root = Path(
        tempfile.mkdtemp(prefix=".worker-rootfs-", dir=output.parent)
    )
    try:
        for relative_path, data in android.items():
            destination = temporary_root / "system" / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(0o755 if relative_path.startswith("bin/") else 0o644)

        for name, data in apple.items():
            destination = temporary_root / "system/lib64" / name
            destination.write_bytes(data)
            destination.chmod(0o644)

        worker_path = temporary_root / "system/bin/apple-music-worker"
        worker_path.write_bytes(worker_data)
        worker_path.chmod(0o755)

        required_directories = (
            "proc",
            "dev",
            "tmp",
            "data/data/com.apple.android.music/files/mpl_db",
            "etc/ssl/certs",
        )
        for relative_path in required_directories:
            (temporary_root / relative_path).mkdir(parents=True, exist_ok=True)

        (temporary_root / "tmp").chmod(0o1777)
        (temporary_root / "data/data/com.apple.android.music/files").chmod(0o700)
        (
            temporary_root / "etc/ssl/certs/ca-certificates.crt"
        ).write_bytes(certificate_bundle)

        metadata = profile_metadata(pins, certificate_bundle)
        (temporary_root / "worker-profile.json").write_text(
            json.dumps(metadata, sort_keys=True) + "\n"
        )

        # mkdir reserves the destination and prevents silently overwriting it.
        output.mkdir()
        for child in temporary_root.iterdir():
            shutil.move(str(child), output / child.name)
    finally:
        shutil.rmtree(temporary_root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument(
        "--arch",
        help="Android ABI or Linux architecture; defaults to the native host",
    )
    parser.add_argument(
        "--android-system",
        type=Path,
        help="override bundled verified Android system binaries (bin/, lib64/, usr/)",
    )
    parser.add_argument(
        "--extract-libraries",
        type=Path,
        help="extract only verified Apple libraries into a new directory",
    )
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--ca-bundle",
        type=Path,
        default=Path("/etc/ssl/certs/ca-certificates.crt"),
    )
    args = parser.parse_args()

    try:
        pins = load_profile(args.arch)
        build_directory = ROOT / "build" / pins["architecture"]

        if args.extract_libraries:
            libraries = extract_apple(args.apk, pins)
            args.extract_libraries.mkdir(parents=True, exist_ok=False)
            for name, data in libraries.items():
                (args.extract_libraries / name).write_bytes(data)
            print(
                "Extracted verified Apple Music build 1109 "
                + pins["architecture"]
                + " libraries."
            )
            return

        android_system = (
            args.android_system
            or ROOT / "vendor/android-system" / pins["architecture"]
        )
        stage(
            args.apk,
            android_system,
            args.worker or build_directory / "android/apple-music-worker",
            args.output or build_directory / "rootfs",
            args.ca_bundle,
            pins,
        )
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        parser.exit(1, str(error) + "\n")

    print("Staged verified " + pins["architecture"] + " rootfs; no account data included.")


if __name__ == "__main__":
    main()
