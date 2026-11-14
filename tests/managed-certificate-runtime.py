"""Explicit disposable Debian guest only: real systemd credentials and TLS.

Acquisition is a local CA adapter; production CF/ACME endpoints are never used.
Run only by the identity-pinned existing inbound VM fixture.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile


def main():
    identity = os.environ['MAY_CERTIFICATE_FIXTURE']
    if os.geteuid() != 0 or Path('/etc/may-inbound-fixture').read_text().strip() != identity or Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != identity.lower():
        raise RuntimeError('Disposable fixture identity required before writes.')
    base = Path('/root/certificate33-fixture')
    base.mkdir(mode=0o700, exist_ok=False)
    repository = Path('/tmp/may-certificate33-input')
    def load(name, file):
        spec = importlib.util.spec_from_file_location(name, repository/file)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
    C, I = load('certificates', 'managed-certificates.py'), load('inbounds', 'inbound-host.py')
    def command(*args): return subprocess.run(args, check=True, capture_output=True, timeout=60).stdout
    command('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(base/'ca.key'),'-out',str(base/'ca.pem'),'-days','90','-subj','/CN=May Round33 Isolated CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
    (base/'extensions').write_text('subjectAltName=DNS:service.example.test\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n')
    for label, days in (('old','10'),('new','60')):
        command('openssl','req','-newkey','rsa:2048','-nodes','-keyout',str(base/(label+'.key')),'-out',str(base/(label+'.csr')),'-subj','/CN=service.example.test')
        command('openssl','x509','-req','-in',str(base/(label+'.csr')),'-CA',str(base/'ca.pem'),'-CAkey',str(base/'ca.key'),'-CAcreateserial','-out',str(base/(label+'.pem')),'-days',days,'-extfile',str(base/'extensions'))
    shutil.copyfile(base/'ca.pem','/usr/local/share/ca-certificates/may-cert33-fixture.crt'); command('update-ca-certificates')
    class LocalCa(C.Host):
        label='old'
        def acquire(self, identifier, settings, token):
            return (base/(self.label+'.pem')).read_bytes(), (base/(self.label+'.key')).read_bytes(), b'{}'
    host=LocalCa(); identifier='a'*32; settings={'Provider':'Cloudflare','Zone':'example.test','Email':'operator@example.test','Domains':['service.example.test'],'PropagationSeconds':30}
    backup='/root/vps-deploy-backups/20261112-010203/protocol-lifecycle'; request={'Action':'Issue','CertificateId':identifier,'Policy':settings,'ExpectedCertificateHash':'Absent','Token':'x'*40}
    os.environ['VPS_CERTIFICATE_PROGRAM']=(repository/'managed-certificates.py').read_text()
    Path('/var/lib/may-vps-deploy').mkdir(mode=0o700,parents=True,exist_ok=True)
    host.snapshot(backup,identifier,'Absent'); observation=host.operate(backup,request)
    assertions=0
    def check(value,message):
        nonlocal assertions
        if not value: raise RuntimeError(message)
        assertions+=1
    check(observation['State']['Enabled'],'Issue did not enable the timer')
    versions=json.loads((repository/'versions.json').read_text()); version=versions['sing_box']; checksum=version['assets']['amd64']['sha256']
    core={'Engine':'sing-box','Version':version['version'],'Artifact':version['assets']['amd64']['name'],'Sha256':checksum}
    model={'Version':1,'Certificates':[dict(Id=identifier,Name='Fixture certificate',Sha256=observation['State']['Sha256'],NotAfter=observation['State']['NotAfter'],Managed=settings)],'Users':[],'Outbounds':[],'Inbounds':[]}
    payload={'Version':1,'Model':model,'Bindings':[],'Configurations':{},'Core':core}
    for index, enabled in enumerate((True,False)):
        inbound=('b' if index==0 else 'c')*32; user=('d' if index==0 else 'e')*32; port=22000+index
        item={'Id':inbound,'Name':'Fixture consumer','Protocol':'AnyTLS','Enabled':enabled,'Listener':{'Address':'127.0.0.1','Port':port},'CertificateId':identifier,'UserIds':[user],'Options':{'ServerName':'service.example.test','EchEnabled':False}}
        model['Inbounds'].append(item)
        config={'log':{'level':'warn'},'dns':{'servers':[{'type':'local','tag':'local'}]},'inbounds':[{'tag':inbound,'type':'anytls','listen':'127.0.0.1','listen_port':port,'users':[{'name':user,'password':'fixture-password-only'}],'tls':{'enabled':True,'server_name':'service.example.test','min_version':'1.3','certificate_path':'/run/credentials/'+I.unit_name(inbound)+'/certificate.pem','key_path':'/run/credentials/'+I.unit_name(inbound)+'/certificate.key'}}],'outbounds':[{'type':'direct','tag':'egress'}],'route':{'final':'egress'}}
        data=I.encoded(config).encode();payload['Configurations'][inbound]=base64.b64encode(data).decode();payload['Bindings'].append({'Id':inbound,'Enabled':enabled,'Sha256':I.digest(data),'ClientSha256':'f'*64,'Port':port,'Address':'127.0.0.1','Udp':False})
    inbounds=I.Host(); inbound_backup='/root/vps-deploy-backups/20261112-010204/protocol-lifecycle'
    affected=[b['Id'] for b in payload['Bindings']];inbounds.snapshot(inbound_backup,'Absent',payload,affected);inbounds.apply(inbound_backup,payload,'Absent',affected)
    check(inbounds.read()['Runtime']['b'*32]['Active'],'Managed credentials did not start real sing-box')
    check(not inbounds.read()['Runtime']['c'*32]['Active'],'Disabled consumer started')
    def fingerprint():
        with socket.create_connection(('127.0.0.1',22000),timeout=5) as raw:
            with ssl.create_default_context().wrap_socket(raw,server_hostname='service.example.test') as connection:
                return hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()
    check(fingerprint()==observation['State']['Sha256'],'Initial TLS certificate differs')
    before=inbounds.read()['Hash'];host.label='new';request=dict(request,Action='Renew',ExpectedCertificateHash=host.observe(identifier)['Hash']);host.snapshot(backup,identifier,request['ExpectedCertificateHash']);observation=host.operate(backup,request)
    check(fingerprint()==observation['State']['Sha256'],'Reload did not expose the renewed certificate')
    check(inbounds.read()['Hash']==before,'Renewal rewrote immutable catalogue/configuration')
    check(not inbounds.read()['Runtime']['c'*32]['Active'],'Renewal started disabled consumer')
    # Execute the actual constrained timer service. The new 60-day certificate
    # is not due, so the production acquisition method must never be reached.
    command('systemctl','start',C.service(identifier)+'.service')
    check(command('systemctl','show',C.service(identifier)+'.service','-p','Result','--value').strip()==b'success','Constrained renewal service failed')
    check(fingerprint()==observation['State']['Sha256'],'Scheduled check altered the certificate')
    request=dict(request,Action='Disable',ExpectedCertificateHash=host.observe(identifier)['Hash']);host.snapshot(backup,identifier,request['ExpectedCertificateHash']);host.operate(backup,request)
    check(fingerprint()==observation['State']['Sha256'],'Disabling renewal changed active TLS')
    check(not host.observe(identifier)['State']['Enabled'],'Timer disable not persisted')
    for name in (C.service(identifier)+'.timer',C.service(identifier)+'.service',I.unit_name('b'*32),I.unit_name('c'*32)):
        subprocess.run(['systemctl','disable','--now',name],capture_output=True,timeout=30)
    check(all(subprocess.run(['systemctl','is-active','--quiet',n],capture_output=True).returncode!=0 for n in (C.service(identifier)+'.timer',I.unit_name('b'*32),I.unit_name('c'*32))),'Owned service still active')
    print(json.dumps({'assertions':assertions,'real_systemd_credentials':True,'real_tls_before_and_after':True,'constrained_timer_success':True,'disabled_consumer_preserved':True,'owned_services_stopped':True,'public_acme_or_cf_used':False}))


if __name__=='__main__':
    main()
