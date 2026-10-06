import hashlib
import json
import sys
from pathlib import Path


def verify(folder):
    manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8-sig'))
    whole = hashlib.sha256()
    total = 0
    parts = manifest['parts']
    if not parts:
        raise ValueError('Empty manifest')
    for index, part in enumerate(parts, 1):
        expected_name = f'LIxian-BaN.7z.{index:03d}'
        if part['name'] != expected_name:
            raise ValueError(f'Invalid part order or filename: {part["name"]}')
        path = folder / expected_name
        if path.stat().st_size != part['size']:
            raise ValueError(f'Wrong size: {expected_name}')
        digest = hashlib.sha256()
        with path.open('rb') as source:
            while data := source.read(8 * 1024 * 1024):
                digest.update(data)
                whole.update(data)
                total += len(data)
        if digest.hexdigest() != part['sha256']:
            raise ValueError(f'SHA256 mismatch: {expected_name}')
        print(f'PASS {index}/{len(parts)} {expected_name}', flush=True)
    if total != manifest['size'] or whole.hexdigest() != manifest['sha256']:
        raise ValueError('Original archive size or SHA256 mismatch')
    print('PASS: all parts and original archive SHA256 match', flush=True)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python verify_parts.py <download-directory>')
    verify(Path(sys.argv[1]))
