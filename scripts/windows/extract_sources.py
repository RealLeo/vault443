#!/usr/bin/env python3
"""Update a native build checkout by content, preserving Ninja dependencies.

The reproducible ZIP has fixed timestamps. Changed files must receive a fresh
build-directory timestamp so CMake AUTOMOC sees changed headers on a rebuild.
"""
import argparse
from pathlib import Path, PurePosixPath
import zipfile
import os


def extract(archive, destination):
    destination.mkdir(parents=True, exist_ok=True)
    marker = destination / '.vault443-content-extraction-v1'
    first = not marker.exists()
    expected = {marker}
    changed = 0
    with zipfile.ZipFile(archive) as source:
        for entry in source.infolist():
            name = PurePosixPath(entry.filename)
            if name.is_absolute() or '..' in name.parts or '\\' in entry.filename or ':' in entry.filename:
                raise ValueError('Invalid source archive member')
            if entry.is_dir():
                continue
            path = destination.joinpath(*name.parts)
            expected.add(path)
            data = source.read(entry)
            if path.is_file() and path.read_bytes() == data:
                if first:
                    os.utime(path, None)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            changed += 1
    for path in destination.rglob('*'):
        if path.is_file() and path not in expected:
            path.unlink()
    marker.touch()
    print(f'Updated {changed} native source files by content', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    extract(args.archive, args.destination)
