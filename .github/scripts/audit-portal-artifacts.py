#!/usr/bin/env python3
"""Audit clean CI image contents before publishing submission artifacts."""
import gzip
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.PIPE)


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


patterns = {
    "private key": re.compile(
        rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"
        rb"\s+[A-Za-z0-9+/=\r\n]{64,}-----END"
    ),
    "GitHub token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    "credential URL": re.compile(rb"https?://[^\s/:@]{2,}:[^\s/@]{4,}@"),
    "local user path": re.compile(rb"/home/techluddite(?:/|\x00|\s)|/srv/projects/odin2-omarchy"),
}


def scan(root):
    count = 0
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        sensitive = (
            ".ssh" in path.relative_to(root).parts
            or relative.startswith(("var/lib/bluetooth/", "var/lib/iwd/", "etc/NetworkManager/system-connections/"))
            or path.name in {"authorized_keys", "known_hosts", "id_rsa", "id_ed25519"}
        )
        if sensitive and path.stat().st_size:
            raise RuntimeError("Nonempty credential/state file: " + relative)
        if relative == "etc/machine-id" and path.read_bytes().strip() not in (b"", b"uninitialized"):
            raise RuntimeError("Initialized machine-id in image")
        tail = b""
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                data = tail + block
                for label, pattern in patterns.items():
                    if pattern.search(data):
                        raise RuntimeError(label + " in " + relative)
                tail = data[-65536:]
        count += 1
    return count


target = Path(sys.argv[1]).resolve()
archives = sorted(target.glob("ROCKNIX-*.tar"))
images = sorted(target.glob("ROCKNIX-*.img.gz"))
assert archives and images, "Image and update archive are both required"
report = {"origin": "Fresh GitHub runner; public ROCKNIX sources/cache and Portal source patch only", "artifacts": []}
with tempfile.TemporaryDirectory(prefix="portal-artifact-audit-") as directory:
    work = Path(directory)
    for index, archive in enumerate(archives):
        folder = work / ("tar-" + str(index))
        folder.mkdir()
        with tarfile.open(archive) as source:
            members = source.getmembers()
            for member in members:
                name = PurePosixPath(member.name)
                assert not name.is_absolute() and ".." not in name.parts
            source.extractall(folder, filter="data")
        systems = list(folder.glob("*/target/SYSTEM"))
        kernels = list(folder.glob("*/target/KERNEL"))
        assert len(systems) == len(kernels) == 1
        system = systems[0]
        filesystem = work / ("system-" + str(index))
        run("unsquashfs", "-no-progress", "-no-xattrs", "-d", str(filesystem), str(system))
        files = scan(folder) + scan(filesystem)
        mic = filesystem / "usr/share/alsa/ucm2/AYN/Odin2/PortalMic.conf"
        assert "SWR_MIC7" in mic.read_text()
        report["artifacts"].append({"name": archive.name, "sha256": sha(archive), "files_scanned": files})
        for image_index, image in enumerate(images):
            disk = work / ("disk-" + str(image_index) + ".img")
            with gzip.open(image, "rb") as source, disk.open("wb") as destination:
                shutil.copyfileobj(source, destination)
            partitions = json.loads(run("sfdisk", "--json", str(disk)))["partitiontable"]
            sector_size = partitions.get("sectorsize", 512)
            entries = partitions["partitions"]
            assert len(entries) == 2, "Unexpected image partitions"
            fat = entries[0]
            offset = fat["start"] * sector_size
            image_system = work / ("fat-system-" + str(image_index))
            image_kernel = work / ("fat-kernel-" + str(image_index))
            fat_tree = work / ("fat-" + str(image_index))
            fat_tree.mkdir()
            run("mcopy", "-s", "-i", str(disk) + "@@" + str(offset), "::*", str(fat_tree))
            fat_files = scan(fat_tree)
            run("mcopy", "-i", str(disk) + "@@" + str(offset), "::/SYSTEM", str(image_system))
            run("mcopy", "-i", str(disk) + "@@" + str(offset), "::/KERNEL", str(image_kernel))
            assert sha(image_system) == sha(system), "Image/update SYSTEM mismatch"
            assert sha(image_kernel) == sha(kernels[0]), "Image/update KERNEL mismatch"
            storage = work / ("storage-" + str(image_index) + ".ext4")
            with disk.open("rb") as source, storage.open("wb") as destination:
                source.seek(entries[1]["start"] * sector_size)
                remaining = entries[1]["size"] * sector_size
                while remaining:
                    block = source.read(min(remaining, 1024 * 1024))
                    assert block
                    destination.write(block)
                    remaining -= len(block)
            storage_tree = work / ("storage-" + str(image_index))
            storage_tree.mkdir()
            run("debugfs", "-R", "rdump / " + str(storage_tree), str(storage))
            files = scan(storage_tree)
            report["artifacts"].append({"name": image.name, "sha256": sha(image), "fat_files_scanned": fat_files, "storage_files_scanned": files, "system_kernel_match_update": True})
            disk.unlink()
print(json.dumps(report, indent=2))
