"""Select the reviewed program or the transaction's immutable recovery program."""
import hashlib
import json
import os
from pathlib import Path
import re


def select(document, action, current, root=Path('/')):
    task, expected = document.get('Task', ''), document.get('ProgramSha256', '')
    if not re.fullmatch('[a-f0-9]{32}', task) or not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('Invalid reviewed address program identity.')
    directory = root / 'root/vps-deploy-address' / task
    saved = directory / 'recovery.py'
    path = current if action in ('Inspect', 'Prepare') or action == 'Status' and not directory.exists() else saved
    if path.is_symlink() or any(p.is_symlink() for p in path.parents) or not path.is_file():
        raise ValueError('Missing or linked address program.')
    st = path.stat()
    if st.st_uid != 0 or st.st_mode & 0o077 or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError('Address program differs from the reviewed snapshot.')
    return path


if __name__ == '__main__':
    document = json.loads(Path(os.environ['VPS_PARAM_ADDRESS_DOCUMENT_FILE']).read_text())
    path = select(document, os.environ['VPS_PARAM_ADDRESS_ACTION'], Path(os.environ['VPS_ADDRESS_PROGRAM_FILE']))
    os.execv('/usr/bin/python3', ['python3', str(path)])
