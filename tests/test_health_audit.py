"""Execute the real audit payload with fake commands, no live registry/VPS reads."""
import base64
import contextlib
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


class HealthAuditTests(unittest.TestCase):
    def audit(self, timeout_command=None, known=True, supported_controller=True):
        with tempfile.TemporaryDirectory(prefix='health-audit-',dir=ROOT/'.tmp') as directory:
            root=Path(directory)
            body=(ROOT/'assets/remote/maintenance-health-audit.sh').read_text().split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
            for prefix in ('/usr/local','/usr/bin','/etc','/opt','/var/lib','/proc'):
                body=body.replace(prefix,root.as_posix()+prefix)
            body=body.replace('os.uname().machine','"x86_64"')
            for relative in ('usr/local/bin/komari-agent','usr/local/bin/cloudflared','etc/komari-agent/config.json','etc/mxh-tls/anytls/fullchain.pem','etc/mxh-tls/reality-target/fullchain.pem','opt/komari/komari'):
                file=root/relative;file.parent.mkdir(parents=True,exist_ok=True);file.write_text('fixture');file.chmod(0o755)
            calls=[]
            def run(args,**kwargs):
                self.assertEqual(kwargs.get('timeout'),10)
                calls.append(args)
                if Path(args[0]).name=='komari-agent':
                    self.fail('health audit executed an Agent instead of identifying its hash')
                if args[0]==timeout_command:
                    raise subprocess.TimeoutExpired(args,10)
                code=0;out=''
                if args[0]=='systemctl':
                    if args[1]=='show':
                        if '--property=MainPID' in args:
                            out='123'
                        elif '--property=WorkingDirectory' in args:
                            out=(root/'opt/komari').as_posix()
                        else:
                            binary='usr/local/bin/komari-agent' if args[-1]=='komari-agent.service' else 'usr/local/bin/cloudflared' if args[-1]=='cloudflared.service' else 'opt/komari/komari' if supported_controller else 'custom/komari'
                            out='{ path='+(root/binary).as_posix()+' ; argv[]=fixture ; }'
                    elif args[1] in ('is-active','is-enabled'):
                        code=0 if args[-1] in ('komari-agent.service','komari.service','mxh-certbot-renew.timer') else 1
                    elif args[1]=='cat':
                        code=0 if args[-1] in ('komari-agent.service','komari.service') else 1
                elif args[0]=='sshd':
                    out='port 30123\nport 31234\npasswordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes\npermitrootlogin prohibit-password\n'
                elif args[0]=='ss':
                    out='tcp LISTEN 0 128 127.0.0.1:30123 0.0.0.0:*\nudp UNCONN 0 0 [::]:33456 [::]:*\ntcp LISTEN 0 128 127.0.0.1:25774 0.0.0.0:*\n'
                elif args[0]=='openssl':
                    out='notAfter='+ (datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=60)).strftime('%b %d %H:%M:%S %Y GMT')
                elif Path(args[0]).name=='komari':
                    out='Komari Monitor 1.5.1'
                elif Path(args[0]).name=='cloudflared':out='cloudflared version 2026.10.0 (built 2026-10-01)'
                return subprocess.CompletedProcess(args,code,out,'')
            digest=hashlib.sha256(b'fixture').hexdigest()
            env={'VPS_PARAM_AGENT_RELEASES_JSON':json.dumps({digest:'1.5.11'} if known else {})}
            output=io.StringIO()
            with patch('subprocess.run',side_effect=run),patch('os.path.samefile',return_value=True),patch.dict(os.environ,env),contextlib.redirect_stdout(output):
                exec(compile(body,'health-payload','exec'),{})
            encoded=next(line.split('=',1)[1] for line in output.getvalue().splitlines() if line.startswith('VPSDEPLOY_HEALTH_AUDIT_B64='))
            return json.loads(base64.b64decode(encoded)),calls

    def test_agent_identified_without_execution(self):
        audit,calls=self.audit()
        self.assertEqual(audit['Versions']['KomariAgent'],'1.5.11')
        self.assertTrue(audit['AgentVersionEvidence']['Identified'])
        self.assertTrue(all(Path(x[0]).name!='komari-agent' for x in calls))
        self.assertTrue(audit['Services']['KomariAgent']['SupportedLayout'])
        self.assertTrue(audit['Services']['KomariController']['SupportedLayout'])

    def test_unknown_controller_layout_is_not_promoted(self):
        audit,_=self.audit(supported_controller=False)
        self.assertTrue(audit['Services']['KomariController']['Installed'])
        self.assertFalse(audit['Services']['KomariController']['SupportedLayout'])

    def test_unknown_agent_is_not_guessed(self):
        audit,_=self.audit(known=False)
        self.assertIsNone(audit['Versions']['KomariAgent'])
        self.assertFalse(audit['AgentVersionEvidence']['Identified'])

    def test_cloudflared_actual_version_is_available_for_upgrade_selection(self):
        audit,calls=self.audit()
        self.assertEqual(audit['Versions']['Cloudflared'],'2026.10.0')
        self.assertTrue(any(Path(args[0]).name=='cloudflared' and args[-1]=='--version' for args in calls))

    def test_audit_timeout_is_bounded_and_marked_incomplete(self):
        audit,_=self.audit(timeout_command='sshd')
        self.assertIn('sshd',audit['ChecksIncomplete'])
        self.assertFalse(audit['Ssh']['Valid'])

    def test_listener_transport_and_both_certificate_roles(self):
        audit,_=self.audit()
        self.assertEqual(audit['Listeners']['Udp'],[33456])
        self.assertEqual(audit['Listeners']['Tcp'],[25774,30123])
        self.assertTrue(audit['Certificates']['Reality']['Present'])
        self.assertTrue(audit['Certificates']['AnyTls']['Present'])
        self.assertGreater(audit['Certificates']['Reality']['DaysRemaining'],50)
        self.assertTrue(audit['Timers']['CertbotRenewActive'])
        self.assertEqual(audit['Versions']['KomariController'],'1.5.1')


if __name__=='__main__':
    (ROOT/'.tmp').mkdir(exist_ok=True)
    unittest.main(verbosity=2)
