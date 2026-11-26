#!/usr/bin/env python3
"""Create a minimal profile-consistent rootfs for Docker-only synthetic tests."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    output = args.output
    output.mkdir(parents=True, exist_ok=False)

    worker = bytearray(64)
    worker[:6] = b"\x7fELF\x02\x01"
    worker[18:20] = int(profile["elf_machine"]).to_bytes(2, "little")

    worker_path = output / "system/bin/apple-music-worker"
    worker_path.parent.mkdir(parents=True, exist_ok=True)
    worker_path.write_bytes(worker)
    worker_path.chmod(0o755)

    session = output / "data/data/com.apple.android.music/files"
    (session / "mpl_db").mkdir(parents=True, exist_ok=True)
    (output / "proc").mkdir()
    (output / "dev").mkdir()
    (output / "tmp").mkdir()
    (output / "etc/ssl/certs").mkdir(parents=True)

    metadata = {
        "architecture": profile["architecture"],
        "profile": profile["profile"],
        "context_profile": profile.get("context_profile"),
        "context_supported": profile["context_supported"],
        "synthetic_test_rootfs": True,
    }
    (output / "worker-profile.json").write_text(
        json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
