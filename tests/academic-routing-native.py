"""Actual client routing against loopback-only DNS, HTTP and proxy fixtures.

No campus login, public site, installed profile, OS proxy or TUN is used. DNS
transports are replaced only in the test copy; public domain rules are unchanged.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]


class ThreadedTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def reply(connection, body):
    connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


class Origin(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        with self.request.makefile("rb") as reader:
            while reader.readline().strip():
                pass
        reply(self.request, b"DIRECT")


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        with self.request.makefile("rb") as reader:
            first = reader.readline()
            while reader.readline().strip():
                pass
            if first.startswith(b"CONNECT "):
                self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                while reader.readline().strip():
                    pass
        reply(self.request, b"PROXY")


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        end = 12
        while data[end]:
            end += data[end] + 1
        end += 1
        question = data[12:end + 4]
        is_a = struct.unpack("!H", data[end:end + 2])[0] == 1
        header = data[:2] + struct.pack("!HHHHH", 0x8180, 1, int(is_a), 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("127.0.0.1") if is_a else b""
        connection.sendto(header + question + answer, self.client_address)


def start_server(stack, kind, handler):
    server = kind(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stack.callback(server.server_close)
    stack.callback(server.shutdown)
    return server.server_address[1]


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def request_api(port, path, method="GET", data=None):
    body = json.dumps(data).encode() if data is not None else None
    request = urllib.request.Request(f"http://127.0.0.1:{port}" + path, data=body, method=method,
                                     headers={"Content-Type": "application/json", "Authorization": "Bearer fixture"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=2) as response:
        return response.read()


def run_client(kind, binary, root, dns_port, proxy_port, origin_port):
    work = root / kind
    work.mkdir()
    mixed, controller = free_port(), free_port()
    if kind == "sing-box":
        original = json.loads((ROOT / "templates/client/sing-box-general.template.json").read_text())
        # Test only the domain policy and explicit modes, with no external rulesets.
        rules = [rule for rule in original["route"]["rules"]
                 if rule.get("outbound") in {"DIRECT", "Academic Research", "Developer Tools"}
                 and (rule.get("domain") or rule.get("domain_suffix"))]
        configuration = {"log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "fixture", "listen": "127.0.0.1", "listen_port": mixed}],
            "dns": {"servers": [{"type": "udp", "tag": "fixture-dns", "server": "127.0.0.1", "server_port": dns_port}]},
            "outbounds": [{"type": "direct", "tag": "DIRECT"},
                          {"type": "http", "tag": "FIXTURE-PROXY", "server": "127.0.0.1", "server_port": proxy_port}] +
                         [{"type": "selector", "tag": name, "outbounds": members, "default": members[0]} for name, members in [
                             ("Default Exit", ["FIXTURE-PROXY"]), ("Direct Route", ["Default Exit", "DIRECT"]),
                             ("Academic Research", ["Direct Route", "Default Exit"]), ("Developer Tools", ["Default Exit", "Direct Route"])]],
            "route": {"default_domain_resolver": {"server": "fixture-dns", "strategy": "ipv4_only"}, "rules": [
                {"clash_mode": "Direct", "action": "route", "outbound": "DIRECT"},
                {"clash_mode": "Global", "action": "route", "outbound": "Default Exit"}] + rules, "final": "Default Exit"},
            "experimental": {"clash_api": {"external_controller": f"127.0.0.1:{controller}", "secret": "fixture", "default_mode": "Rule"}}}
        path = work / "config.json"
        path.write_text(json.dumps(configuration), encoding="utf-8")
        command = [str(binary), "run", "-D", str(work), "-c", str(path)]
    else:
        original = YAML(typ="safe").load((ROOT / "templates/client/clash-general.template.yaml").read_text())
        rules = [rule for rule in original["rules"] if rule.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")) and
                 rule.split(",")[-1] in {"DIRECT", "Academic Research", "Developer Tools"}]
        configuration = {"mixed-port": mixed, "allow-lan": False, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "error",
            "external-controller": f"127.0.0.1:{controller}", "secret": "fixture",
            "dns": {"enable": True, "listen": f"127.0.0.1:{free_port()}", "nameserver": [f"udp://127.0.0.1:{dns_port}"]},
            "proxies": [{"name": "FIXTURE-PROXY", "type": "http", "server": "127.0.0.1", "port": proxy_port}],
            "proxy-groups": [{"name": name, "type": "select", "proxies": members} for name, members in [
                ("Default Exit", ["FIXTURE-PROXY"]), ("Direct Route", ["Default Exit", "DIRECT"]),
                ("Academic Research", ["Direct Route", "Default Exit"]), ("Developer Tools", ["Default Exit", "Direct Route"])]],
            "rules": rules + ["MATCH,Default Exit"]}
        path = work / "config.yaml"
        with path.open("w", encoding="utf-8") as output:
            YAML().dump(configuration, output)
        command = [str(binary), "-d", str(work), "-f", str(path)]
    with (work / "core.log").open("wb") as log:
        process = subprocess.Popen(command, stdout=log, stderr=log,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError(kind + " fixture exited: " + (work / "core.log").read_text(errors="replace")[-1000:])
                try:
                    request_api(controller, "/version")
                    break
                except (OSError, urllib.error.URLError):
                    time.sleep(.05)
            else:
                raise RuntimeError(kind + " fixture did not become ready")
            def select(group, name):
                request_api(controller, "/proxies/" + urllib.parse.quote(group, safe=""), "PUT", {"name": name})
            def expect(host, body):
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{mixed}"}))
                with opener.open(f"http://{host}:{origin_port}/fixture", timeout=4) as response:
                    actual = response.read(32).decode()
                if actual != body:
                    raise AssertionError(f"{kind}: {host}: expected {body}, got {actual}")
            # Even a user-selected proxy in Direct Route must not capture campus traffic.
            expect("sysu.co.cnki.net", "DIRECT")
            expect("cas.sysu.edu.cn", "DIRECT")
            select("Direct Route", "DIRECT")
            for host in ["www.sciencedirect.com", "id.elsevier.com", "pdf.sciencedirectassets.com", "scholar.google.com",
                         "webofscience.clarivate.cn", "link.springernature.com", "research.ebsco.com",
                         "signin.ebsco.zone", "content.ebsco-content.com"]:
                expect(host, "DIRECT")
            select("Academic Research", "Default Exit")
            expect("pdf.sciencedirectassets.com", "PROXY")
            expect("scholar.google.com", "PROXY")
            expect("sysu.co.cnki.net", "DIRECT")
            expect("openxla.org", "PROXY")
            if kind == "mihomo":
                select("GLOBAL", "FIXTURE-PROXY")
            request_api(controller, "/configs", "PATCH", {"mode": "global"})
            expect("sysu.co.cnki.net", "PROXY")
            print("PASS:", kind, "16 actual routing checks; campus, academic selection, PDF/login chain, explicit global mode")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sing-box", type=Path, required=True)
    parser.add_argument("--mihomo", type=Path, required=True)
    args = parser.parse_args()
    (ROOT / ".tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="academic-native-", dir=ROOT / ".tmp") as directory, contextlib.ExitStack() as stack:
        dns = start_server(stack, socketserver.UDPServer, DNS)
        proxy = start_server(stack, ThreadedTCP, Proxy)
        origin = start_server(stack, ThreadedTCP, Origin)
        run_client("sing-box", args.sing_box, Path(directory), dns, proxy, origin)
        run_client("mihomo", args.mihomo, Path(directory), dns, proxy, origin)


if __name__ == "__main__":
    main()
