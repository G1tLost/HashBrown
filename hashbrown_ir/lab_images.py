"""Inert fixtures; never captures host RAM or disks.

Adapted from MIT-licensed Bacon Egg and Cheese contributors; see THIRD_PARTY_NOTICES.md.
"""
import struct
from pathlib import Path

from .storage import CaseError, digest, encode


def disk_fixture():
    # A valid FAT12 floppy-sized image with a harmless README in cluster two.
    image = bytearray(1474560)
    image[:11] = b"\xeb\x3c\x90HASHLAB "
    struct.pack_into("<HBHBHHBHHHII", image, 11, 512, 1, 1, 2, 224, 2880, 0xF0, 9, 18, 2, 0, 0)
    image[38] = 0x29
    struct.pack_into("<I", image, 39, 0x48420001)
    image[43:54] = b"HASHBROWN  "
    image[54:62] = b"FAT12   "
    image[510:512] = b"\x55\xaa"
    content = b"HashBrown synthetic disk acquisition exercise.\r\nNo ransomware or encrypted user data is present.\r\n"
    for sector in (1, 10):
        start = sector * 512
        image[start:start + 5] = b"\xf0\xff\xff\xff\x0f"
    root = 19 * 512
    image[root:root + 11] = b"README  TXT"
    image[root + 11] = 0x20
    struct.pack_into("<H", image, root + 26, 2)
    struct.pack_into("<I", image, root + 28, len(content))
    image[33 * 512:33 * 512 + len(content)] = content
    return bytes(image)


def memory_fixture():
    # This is a transfer fixture, not a Windows RAM image accepted by Volatility.
    marker = b"HashBrown SYNTHETIC MEMORY TRANSFER FIXTURE\x00NOT A LIVE MEMORY IMAGE\x00"
    data = bytearray(3 * 1024 * 1024 + 4096)
    for pos in (0, 1048500, 2097100, len(data) - len(marker)):
        data[pos:pos + len(marker)] = marker
    data[4096:4352] = bytes(range(256))
    return bytes(data)


def create_fixtures(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    payloads = {"disk.img": disk_fixture(), "memory.raw": memory_fixture()}
    manifest = dict(simulation=True, description="Inert HashBrown lab fixtures; memory.raw is not a live Windows RAM dump.",
                    files={name: dict(bytes=len(raw), sha256=digest(raw)) for name, raw in payloads.items()})
    payloads["fixture-manifest.json"] = encode(manifest)
    for name, raw in payloads.items():
        path = directory / name
        if path.exists() and (not path.is_file() or path.read_bytes() != raw):
            raise CaseError("Fixture generation would replace a different file: " + str(path))
    for name, raw in payloads.items():
        if not (directory / name).exists():
            (directory / name).write_bytes(raw)
    return manifest

