"""Disposable loopback SSH/SFTP server; all credentials and keys are synthetic."""
import argparse
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import paramiko

logging.getLogger("paramiko").setLevel(logging.CRITICAL)
parser = argparse.ArgumentParser()
parser.add_argument("--ready", required=True)
parser.add_argument("--stats", required=True)
parser.add_argument("--operations", action="store_true")
args = parser.parse_args()
stats = {"auth": 0, "exec": 0, "uploads": 0, "chmod": 0, "script_exec": 0, "cleanup": 0, "temporary_files": 0}
lock = threading.RLock()
files = {"/fixture/read-only.txt": (b"fixture-read-only\n", 0o100600)}
temporary_directory = "/tmp/mxh-vps.FIXTURE001"
temporary_script = temporary_directory + "/operation.sh"
success_payload = "# MXH_TRANSPORT_FIXTURE\nset -euo pipefail\nprintf 'VPSDEPLOY_SCRIPT_OK\\n'\n" + "# 中文节点\n" * 4096
failure_payload = "# MXH_TRANSPORT_FIXTURE\nprintf 'fixture-error-details\\n' >&2\nexit 7\n"
denied_payload = success_payload + "# DENY_PERMISSIONS\n"

if sys.platform == "win32":
    git = shutil.which("git")
    bash = str(Path(git).parent.parent / "bin/bash.exe") if git else ""
else:
    bash = shutil.which("bash") or ""
if args.operations and not Path(bash).is_file():
    raise RuntimeError("The transport fixture requires a local Bash runtime.")


def count(name):
    with lock:
        stats[name] += 1
        Path(args.stats).write_text(json.dumps(stats), encoding="utf-8")

def record(**values):
    with lock:
        stats.update(values)
        stats["temporary_files"] = sum(path in files for path in (temporary_script, temporary_directory + "/kernel.deb"))
        Path(args.stats).write_text(json.dumps(stats), encoding="utf-8")


def attributes(path):
    if path not in files:
        return paramiko.SFTP_NO_SUCH_FILE
    data, mode = files[path]
    result = paramiko.SFTPAttributes()
    result.st_size = len(data)
    result.st_mode = mode
    result.st_uid = result.st_gid = 0
    result.st_atime = result.st_mtime = 0
    return result


class MemoryHandle(paramiko.SFTPHandle):
    def __init__(self, path, flags):
        super().__init__(flags)
        self.path = path

    def read(self, offset, length):
        return files[self.path][0][offset:offset + length]

    def write(self, offset, data):
        previous, mode = files[self.path]
        if offset < 0 or offset + len(data) > 1048576:
            return paramiko.SFTP_FAILURE
        files[self.path] = (previous[:offset] + data + previous[offset + len(data):], mode)
        record(upload_bytes=len(files[self.path][0]), upload_has_cr=b"\r" in files[self.path][0])
        if data.startswith(b"MXH_CANCEL_UPLOAD_FIXTURE\n") and offset == 0:
            # Let the caller cancel an actual in-flight transfer after its first write.
            Path(args.ready).with_suffix(".upload-started").write_text("ready", encoding="utf-8")
            time.sleep(0.5)
        return paramiko.SFTP_OK

    def stat(self):
        return attributes(self.path)


class MemorySftp(paramiko.SFTPServerInterface):
    def canonicalize(self, path):
        return path

    def stat(self, path):
        return attributes(path)

    lstat = stat

    def open(self, path, flags, attr):
        if flags & (os.O_WRONLY | os.O_RDWR):
            if path not in (temporary_script, temporary_directory+'/kernel.deb') or path in files:
                return paramiko.SFTP_PERMISSION_DENIED
            files[path] = (b"", 0o100644)
            count("uploads")
            record()
        elif path not in files:
            return paramiko.SFTP_NO_SUCH_FILE
        return MemoryHandle(path, flags)

    def chattr(self, path, attr):
        if path not in (temporary_script, temporary_directory+'/kernel.deb') or path not in files:
            return paramiko.SFTP_PERMISSION_DENIED
        if files[path][0] == denied_payload.encode():
            return paramiko.SFTP_PERMISSION_DENIED
        data, mode = files[path]
        files[path] = (data, attr.st_mode if attr.st_mode is not None else mode)
        count("chmod")
        record(last_mode=files[path][1] & 0o777)
        return paramiko.SFTP_OK


def execute(channel, command):
    # Complete the SSH request acknowledgement before returning command output.
    time.sleep(0.05)
    output, error, status = b"", b"", 0
    if command == "umask 077; mktemp -d /tmp/mxh-vps.XXXXXXXXXX":
        output = (temporary_directory + "\n").encode()
    elif command == "bash '" + temporary_script + "'":
        payload, mode = files.get(temporary_script, (b"", 0))
        if mode & 0o777 != 0o600 or payload not in (success_payload.encode(), failure_payload.encode()):
            status = 126
        else:
            count("script_exec")
            result = subprocess.run([bash, "-s"], input=payload, capture_output=True, timeout=10, cwd=Path(args.ready).parent)
            output, error, status = result.stdout, result.stderr, result.returncode
    elif command in ("rm -f -- '" + temporary_script + "'; rmdir -- '" + temporary_directory + "'", "rm -f -- '" + temporary_directory + "/kernel.deb'; rmdir -- '" + temporary_directory + "'"):
        files.pop(temporary_script if temporary_script in command else temporary_directory+'/kernel.deb', None)
        count("cleanup")
        record()
    else:
        status = 126
    try:
        if output:
            channel.sendall(output)
        if error:
            channel.sendall_stderr(error)
        channel.send_exit_status(status)
    finally:
        channel.close()


class Server(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        count("auth")
        return paramiko.AUTH_SUCCESSFUL if username == "fixture" and password == "fixture-only" else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        count("exec")
        if not args.operations:
            return False
        threading.Thread(target=execute, args=(channel, command.decode()), daemon=True).start()
        return True


key = paramiko.RSAKey.generate(2048)
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(8)
Path(args.stats).write_text(json.dumps(stats), encoding="utf-8")
Path(args.ready).write_text(json.dumps({"port": listener.getsockname()[1]}), encoding="utf-8")


def handle(client):
    transport = paramiko.Transport(client)
    try:
        transport.add_server_key(key)
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, MemorySftp if args.operations else paramiko.SFTPServerInterface)
        transport.start_server(server=Server())
        while transport.is_active():
            time.sleep(0.05)
    except (paramiko.SSHException, EOFError, OSError):
        pass
    finally:
        transport.close()


while True:
    client, address = listener.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
