// Optional cross-project integration: pure profile preparation and CLI check only.
// Never launch the desktop app, change Windows proxy settings or start TUN.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, mkdtemp, readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [projectRoot, desktopRoot, corePath, work] = process.argv.slice(2);
if (!projectRoot || !desktopRoot || !corePath || !work) throw Error('Expected project, May Route source, isolated CLI core and output directory');
const { PublicRuleCache, portablePublicRules } = await import(pathToFileURL(join(desktopRoot, 'src/main/publicRules.ts')).href);
const { buildRuntimeConfig, readSystemProxyEndpoint } = await import(pathToFileURL(join(desktopRoot, 'src/main/runtimeConfig.ts')).href);
const run = promisify(execFile);
const original = await readFile(join(projectRoot, 'templates/client/sing-box-general.template.json'), 'utf8');
await mkdir(work, { recursive: true });
const cacheRoot = await mkdtemp(join(work, 'empty-cache-'));
assert.equal((await readdir(cacheRoot)).length, 0);
let requests = 0;
const offline = async () => { requests++; throw Error('Network intentionally disabled'); };
const cache = new PublicRuleCache(cacheRoot, offline, join(desktopRoot, 'resources/public-rules-v1.json'));
const prepared = await cache.prepare(original);
const rules = JSON.parse(prepared).route.rule_set;
assert.equal(rules.length, 5);
assert.ok(rules.every((rule: any) => typeof rule.initial_path === 'string'));
assert.equal(requests, 0);
assert.deepEqual(JSON.parse(portablePublicRules(prepared)), JSON.parse(original));
for (const mode of ['system-proxy', 'tun'] as const) {
  const directory = join(work, mode);
  await mkdir(directory, { recursive: true });
  const runtime = buildRuntimeConfig(prepared, mode);
  const config = JSON.parse(runtime);
  const inbound = config.inbounds.find((item: any) => item.type === 'tun');
  if (mode === 'system-proxy') {
    assert.equal(inbound.auto_route, false);
    assert.equal(inbound.platform.http_proxy.enabled, true);
    assert.deepEqual(readSystemProxyEndpoint(runtime), { server: '127.0.0.1', port: 2080 });
  } else {
    assert.equal(inbound.auto_route, true);
    assert.equal(inbound.strict_route, true);
    assert.equal(inbound.platform?.http_proxy, undefined);
  }
  const path = join(directory, 'runtime.json');
  await writeFile(path, runtime);
  await run(corePath, ['check', '-D', directory, '-c', path], { windowsHide: true, timeout: 60_000 });
}
assert.equal(requests, 0);
console.log('May Route integration passed: empty-cache offline initialization, portable export, system-proxy and TUN runtime checks; no app/proxy changes');
