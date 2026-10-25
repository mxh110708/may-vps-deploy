"""Create three disposable QEMU guests for the explicit --tcp-chain-vm test.

Uses existing downloaded official Debian images and a portable QEMU runtime.
Only guest NICs change: isolated socket links join front -> relay -> landing;
the controller receives loopback SSH/application forwards, never host routes.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--core-archive', required=True, type=Path)
    parser.add_argument('--project', required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path('/dev/kvm').exists():
        raise RuntimeError('Explicit disposable KVM fixture requires WSL root and KVM.')
    root = args.output.resolve()
    if '/Pywork/.codex-tmp/' not in str(root):
        raise RuntimeError('Use a new workspace .codex-tmp output directory.')
    root.mkdir(exist_ok=False, parents=True)
    versions = json.loads((args.project / 'config/versions.json').read_text())
    expected = versions['sing_box']['assets']['amd64']['sha256']
    if hashlib.sha256(args.core_archive.read_bytes()).hexdigest() != expected:
        raise RuntimeError('Pinned official sing-box archive hash does not match.')
    qemu = args.runtime / 'qemu'
    env = dict(os.environ, LD_LIBRARY_PATH=str(qemu / 'usr/lib/x86_64-linux-gnu'), QEMU_MODULE_DIR=str(qemu / 'usr/lib/x86_64-linux-gnu/qemu'))

    def command(argv, **kwargs):
        result = subprocess.run([str(v) for v in argv], capture_output=True, text=True, **kwargs)
        if result.returncode:
            raise RuntimeError('Disposable fixture command failed: ' + result.stderr[-2200:] + result.stdout[-1200:])
        return result

    def port():
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            return listener.getsockname()[1]

    link12, link23 = port(), port()
    nodes, processes = {}, []
    specs = [
        ('Landing', 13, '198.51.100.30', [('52:54:00:12:03:02', '198.51.100.30/24', 'listen=127.0.0.1:' + str(link23))]),
        ('Relay', 13, '192.0.2.20', [('52:54:00:12:02:01', '192.0.2.20/24', 'listen=127.0.0.1:' + str(link12)), ('52:54:00:12:02:02', '198.51.100.20/24', 'connect=127.0.0.1:' + str(link23))]),
        ('Front', 12, '192.0.2.10', [('52:54:00:12:01:01', '192.0.2.10/24', 'connect=127.0.0.1:' + str(link12))]),
    ]
    try:
        for name, version, address, links in specs:
            work = root / name
            work.mkdir()
            key = work / 'id_ed25519'
            command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key])
            identity = str(uuid.uuid4())
            (work / 'meta-data').write_text('instance-id: may-tcp-chain-' + identity + '\nlocal-hostname: may-chain-' + name.lower() + '\n')
            (work / 'user-data').write_text('#cloud-config\ndisable_root: false\nssh_pwauth: false\nssh_authorized_keys:\n  - ' + key.with_suffix('.pub').read_text().strip() + '\npackage_update: true\npackages: [nftables, python3, iproute2]\nwrite_files:\n  - path: /etc/may-tcp-chain-fixture\n    permissions: "0600"\n    content: ' + identity + '\n  - path: /etc/ssh/sshd_config.d/30-may-test-ports.conf\n    content: |\n      Port 22\n      Port 2222\nruncmd:\n  - [systemctl, restart, ssh]\n')
            command([qemu / 'usr/bin/genisoimage', '-quiet', '-output', work / 'seed.iso', '-volid', 'cidata', '-joliet', '-rock', work / 'user-data', work / 'meta-data'], env=env)
            image = args.runtime / 'images' / ('debian-' + str(version) + '-genericcloud-amd64.qcow2')
            overlay = work / 'disk.qcow2'
            command([qemu / 'usr/bin/qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', image, overlay, '5G'], env=env)
            ssh_port, rescue, app = port(), port(), port()
            direct = []
            if version == 13:
                boot = json.loads((args.runtime / 'images/direct-boot.json').read_text())
                direct = ['-kernel', str(args.runtime / 'images/debian-13-vmlinuz'), '-initrd', str(args.runtime / 'images/debian-13-initrd'), '-append', 'root=PARTUUID=' + boot['partuuid'] + ' ro console=ttyS0,115200']
            arguments = [str(qemu / 'usr/bin/qemu-system-x86_64'), '-enable-kvm', '-cpu', 'host', *direct, '-m', '768', '-smp', '2', '-uuid', identity, '-bios', str(qemu / 'usr/share/seabios/bios-256k.bin'), '-L', str(qemu / 'usr/share/qemu'), '-display', 'none', '-vga', 'none', '-monitor', 'none', '-serial', 'file:' + str(work / 'serial.log'), '-drive', 'file=' + str(overlay) + ',if=virtio,format=qcow2', '-drive', 'file=' + str(work / 'seed.iso') + ',media=cdrom,readonly=on', '-device', 'virtio-rng-pci', '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22,hostfwd=tcp:127.0.0.1:{rescue}-:2222,hostfwd=tcp:127.0.0.1:{app}-:18443', '-device', 'virtio-net-pci,netdev=net0,romfile=']
            for i, (mac, ip, backend) in enumerate(links):
                arguments += ['-netdev', 'socket,id=link' + str(i) + ',' + backend, '-device', 'virtio-net-pci,netdev=link' + str(i) + ',mac=' + mac + ',romfile=']
            process = subprocess.Popen(arguments, env=env, stdout=(work / 'qemu.log').open('w'), stderr=subprocess.STDOUT)
            processes.append(process)
            ssh = ['ssh', '-i', str(key), '-p', str(ssh_port), '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' + str(work / 'known_hosts'), '-o', 'ConnectTimeout=3', '-o', 'BatchMode=yes', 'root@127.0.0.1']
            nodes[name] = {'Name': name, 'Address': address, 'ManagementPort': ssh_port, 'RescuePort': rescue, 'ApplicationPort': app, 'FixtureId': identity, 'KeyFile': command(['wslpath', '-w', key]).stdout.strip(), 'Pid': process.pid, 'Debian': version}
            (work / 'session.json').write_text(json.dumps(dict(nodes[name], Ssh=ssh)))
            for attempt in range(100):
                if process.poll() is not None:
                    raise RuntimeError('QEMU startup failed: ' + (work / 'qemu.log').read_text()[-1200:])
                response = subprocess.run(ssh + ['true'], capture_output=True, timeout=6)
                if response.returncode == 0:
                    break
                time.sleep(2)
            else:
                raise RuntimeError('Disposable SSH startup timed out.')
            command(ssh + ['cloud-init status --wait'], timeout=420)
            guard = command(ssh + ['python3 -c "from pathlib import Path; print(Path(\'/etc/may-tcp-chain-fixture\').read_text().strip()); print(Path(\'/sys/class/dmi/id/product_uuid\').read_text().strip())"']).stdout.lower().split()
            if guard != [identity, identity]:
                raise RuntimeError('Disposable identity mismatch; no commands applied.')
            network = "import json,subprocess\nlinks=" + repr([(mac, ip) for mac, ip, _ in links]) + "\nfor mac,address in links:\n for link in json.loads(subprocess.check_output(['ip','-j','link'])):\n  if link.get('address','').lower()==mac:\n   subprocess.run(['ip','link','set',link['ifname'],'up'],check=True)\n   subprocess.run(['ip','address','replace',address,'dev',link['ifname']],check=True)\n"
            script = "set -euo pipefail\ninstall -d -m 0700 /opt/may-tcp-chain-fixture\nprintf '%s' '" + base64.b64encode(network.encode()).decode() + "' | base64 -d > /opt/may-tcp-chain-fixture/network.py\ncat > /etc/systemd/system/may-tcp-chain-network.service <<'EOF'\n[Unit]\nDescription=Disposable TCP chain test NICs\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 /opt/may-tcp-chain-fixture/network.py\nRemainAfterExit=yes\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl daemon-reload\nsystemctl enable --now may-tcp-chain-network.service\n"
            command(ssh + ['bash -se'], input=script, timeout=30)
            print(name, 'Debian', version, 'disposable guest ready', flush=True)
            if name == 'Landing':
                import io
                with tarfile.open(args.core_archive) as archive:
                    entry = next(m for m in archive.getmembers() if m.isfile() and m.name.endswith('/sing-box'))
                    core = archive.extractfile(entry).read()
                payload = io.BytesIO()
                with tarfile.open(fileobj=payload, mode='w:gz') as archive:
                    entry = tarfile.TarInfo('sing-box'); entry.size = len(core); entry.mode = 0o755; archive.addfile(entry, io.BytesIO(core))
                subprocess.run(ssh + ['tar -xzf - -C /opt/may-tcp-chain-fixture'], input=payload.getvalue(), check=True, timeout=60)
        manifest = {'Version': 1, 'SyntheticOnly': True, 'Nodes': nodes, 'StopFile': str(root / 'stop'), 'CreatedAt': time.time()}
        (root / 'manifest.private.json').write_text(json.dumps(manifest, indent=2))
        print('READY: three disposable guests; waiting for explicit stop marker', flush=True)
        for _ in range(3600):
            if (root / 'stop').exists():
                break
            if any(p.poll() is not None for p in processes):
                raise RuntimeError('A disposable guest exited unexpectedly.')
            time.sleep(1)
        else:
            raise RuntimeError('Fixture lifetime exceeded one hour.')
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=10)
        print('Disposable QEMU processes stopped; host and production networking untouched.', flush=True)


if __name__ == '__main__':
    main()
