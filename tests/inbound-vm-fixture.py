"""Explicit disposable Debian fixture for --inbounds-vm; never production."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import time
import uuid
import ipaddress
import secrets
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--core-archive', required=True, type=Path)
    parser.add_argument('--xray-archive', required=True, type=Path)
    parser.add_argument('--project', required=True, type=Path)
    parser.add_argument('--debian', required=True, type=int, choices=(12, 13))
    parser.add_argument('--quic', action='store_true')
    args = parser.parse_args()
    root = args.output.resolve()
    if os.geteuid() != 0 or not Path('/dev/kvm').exists() or '/Pywork/.codex-tmp/' not in str(root):
        raise RuntimeError('Use the explicit WSL KVM fixture and a fresh workspace output directory.')
    root.mkdir(exist_ok=False, parents=True)
    versions = json.loads((args.project/'config/versions.json').read_text())
    core = versions['sing_box']; archive_hash = core['assets']['amd64']['sha256']
    content = args.core_archive.read_bytes()
    if hashlib.sha256(content).hexdigest() != archive_hash:
        raise RuntimeError('Official core archive differs from its fixed digest.')
    xray_content=args.xray_archive.read_bytes();xray=versions['xray']
    if hashlib.sha256(xray_content).hexdigest()!=xray['assets']['amd64']['sha256']: raise RuntimeError('Official Xray archive differs from its fixed digest.')
    qemu = args.runtime/'qemu'
    env = dict(os.environ, LD_LIBRARY_PATH=str(qemu/'usr/lib/x86_64-linux-gnu'), QEMU_MODULE_DIR=str(qemu/'usr/lib/x86_64-linux-gnu/qemu'))

    def command(argv, **kwargs):
        result = subprocess.run([str(v) for v in argv], capture_output=True, text=True, **kwargs)
        if result.returncode:
            raise RuntimeError('Disposable fixture failed: '+result.stderr[-1800:]+result.stdout[-800:])
        return result

    ports = set()
    def port():
        while True:
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0)); value = listener.getsockname()[1]
            if value not in ports:
                ports.add(value); return value

    identity = str(uuid.uuid4()); key = root/'id_ed25519'
    command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key])
    (root/'meta-data').write_text('instance-id: may-inbounds-'+identity+'\nlocal-hostname: may-inbound-fixture\n')
    (root/'user-data').write_text('#cloud-config\ndisable_root: false\nssh_pwauth: false\nssh_authorized_keys:\n  - '+key.with_suffix('.pub').read_text().strip()+'\npackages: [nftables, python3, iproute2]\nwrite_files:\n  - path: /etc/may-inbound-fixture\n    permissions: "0600"\n    content: '+identity+'\n  - path: /etc/ssh/sshd_config.d/30-may-test-ports.conf\n    content: |\n      Port 22\n      Port 2222\nruncmd:\n  - [systemctl, restart, ssh]\n')
    command([qemu/'usr/bin/genisoimage', '-quiet', '-output', root/'seed.iso', '-volid', 'cidata', '-joliet', '-rock', root/'user-data', root/'meta-data'], env=env)
    command([qemu/'usr/bin/qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', args.runtime/'images'/f'debian-{args.debian}-genericcloud-amd64.qcow2', root/'disk.qcow2', '5G'], env=env)
    ssh_port, rescue = port(), port(); applications = {str(n):port() for n in range(22000, 22008)}
    forwarding = f'user,id=net0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22,hostfwd=tcp:127.0.0.1:{rescue}-:2222'+''.join(f',hostfwd=tcp:127.0.0.1:{host}-:{guest}' for guest, host in applications.items())
    udp_address='';udp_ports={}
    if args.quic:
        addresses=json.loads(command(['ip','-j','-4','address','show']).stdout)
        udp_address=next(a['local'] for device in addresses if device.get('ifname')!='lo' for a in device.get('addr_info',[]) if a.get('scope')=='global' and ipaddress.ip_address(a['local']).is_private)
        if not ipaddress.ip_address(udp_address).is_private: raise RuntimeError('QUIC fixture requires a private WSL interface.')
        for number in range(22000,22008):
            with socket.socket(type=socket.SOCK_DGRAM) as probe:probe.bind((udp_address,0));udp_ports[str(number)]=probe.getsockname()[1]
        forwarding+=''.join(f',hostfwd=udp:{udp_address}:{host}-:{guest}' for guest,host in udp_ports.items())
    direct = []
    if args.debian == 13:
        boot = json.loads((args.runtime/'images/direct-boot.json').read_text())
        direct = ['-kernel', str(args.runtime/'images/debian-13-vmlinuz'), '-initrd', str(args.runtime/'images/debian-13-initrd'), '-append', 'root=PARTUUID='+boot['partuuid']+' ro console=ttyS0,115200']
    argv = [str(qemu/'usr/bin/qemu-system-x86_64'), '-enable-kvm', '-cpu', 'host', *direct, '-m', '768', '-smp', '2', '-uuid', identity, '-bios', str(qemu/'usr/share/seabios/bios-256k.bin'), '-L', str(qemu/'usr/share/qemu'), '-display', 'none', '-vga', 'none', '-monitor', 'none', '-serial', 'file:'+str(root/'serial.log'), '-drive', 'file='+str(root/'disk.qcow2')+',if=virtio,format=qcow2', '-drive', 'file='+str(root/'seed.iso')+',media=cdrom,readonly=on', '-device', 'virtio-rng-pci', '-netdev', forwarding, '-device', 'virtio-net-pci,netdev=net0,romfile=']
    process = subprocess.Popen(argv, env=env, stdout=(root/'qemu.log').open('w'), stderr=subprocess.STDOUT)
    tunnel=None
    try:
        ssh = ['ssh','-i',str(key),'-p',str(ssh_port),'-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(root/'known_hosts'),'-o','ConnectTimeout=3','-o','BatchMode=yes','root@127.0.0.1']
        for _ in range(100):
            if process.poll() is not None: raise RuntimeError('Disposable QEMU exited.')
            if subprocess.run(ssh+['true'],capture_output=True,timeout=6).returncode == 0: break
            time.sleep(2)
        else: raise RuntimeError('Disposable SSH startup timed out.')
        command(ssh+['cloud-init status --wait'],timeout=420)
        proof = command(ssh+["python3 -c \"from pathlib import Path; print(Path('/etc/may-inbound-fixture').read_text().strip()); print(Path('/sys/class/dmi/id/product_uuid').read_text().strip())\""]).stdout.lower().split()
        if proof != [identity,identity]: raise RuntimeError('Fixture identity mismatch; no mutation allowed.')
        with tarfile.open(fileobj=io.BytesIO(content)) as archive:
            binary = archive.extractfile(next(m for m in archive.getmembers() if m.isfile() and m.name.endswith('/sing-box'))).read()
        with zipfile.ZipFile(io.BytesIO(xray_content)) as archive:xray_binary=archive.read('xray')
        for engine,version,checksum,data in [('sing-box',core['version'],archive_hash,binary),('xray',xray['version'],xray['assets']['amd64']['sha256'],xray_binary)]:
            directory = '/usr/local/lib/may-inbound-cores/'+checksum
            metadata = json.dumps({'Managed':'MayInboundCore.v1','Version':version,'ArchiveSha256':checksum,'BinarySha256':hashlib.sha256(data).hexdigest()}).encode()
            setup = 'set -euo pipefail\numask 077\ninstall -d -m 0755 '+directory+'\n'
            setup += "base64 -d > "+directory+"/core.json <<'MAY_SYNTHETIC_CORE'\n"+base64.b64encode(metadata).decode()+"\nMAY_SYNTHETIC_CORE\n"
            command(ssh+['bash -s'],input=setup,timeout=100)
            # Stream core-sized data rather than retaining it in Bash parsing.
            binary_file=root/engine; binary_file.write_bytes(data)
            command(['scp','-q','-P',str(ssh_port),'-i',str(key),'-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(root/'known_hosts'),binary_file,'root@127.0.0.1:'+directory+'/'+engine],timeout=100)
            command(ssh+['chmod 0755 '+directory+'/'+engine+' && chmod 0644 '+directory+'/core.json'])
        manifest = {'Version':1,'SyntheticOnly':True,'Debian':args.debian,'FixtureId':identity,'Name':'Inbound','Address':'10.0.2.15','ManagementPort':ssh_port,'RescuePort':rescue,'Applications':applications,'UdpAddress':udp_address,'UdpApplications':udp_ports,'KeyFile':command(['wslpath','-w',key]).stdout.strip(),'Pid':process.pid}
        if args.quic:
            from quic_vm_tunnel import start
            manifest['DatagramTunnelToken']=secrets.token_hex(24);tunnel=start(manifest);manifest['DatagramTunnelPort']=tunnel.server_address[1]
        (root/'manifest.private.json').write_text(json.dumps(manifest,indent=2))
        print('READY: Debian '+str(args.debian)+' disposable inbound fixture',flush=True)
        for _ in range(3600):
            if (root/'stop').exists(): break
            if process.poll() is not None: raise RuntimeError('Disposable guest exited unexpectedly.')
            time.sleep(1)
    finally:
        if tunnel is not None:tunnel.shutdown();tunnel.server_close()
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
        print('STOPPED: disposable QEMU process; host and production routes untouched.',flush=True)


if __name__ == '__main__':main()
