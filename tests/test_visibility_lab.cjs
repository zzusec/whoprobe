'use strict';

// node --test tests/test_visibility_lab.cjs
// node tests/test_visibility_lab.cjs --fixture   (loopback-only browser fixture)
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const test = require('node:test');
const makeLab = require('../static/visibility-lab.js');
const { helpers } = makeLab();

if (process.argv.includes('--fixture')) {
  startFixture().catch(err => { console.error(err); process.exitCode = 1; });
} else {
  const token = 'a'.repeat(32);
  const sample = (httpVersion, alpn, source = 'trusted-edge') => ({ ok: true, challenge: token,
    peer: { ip: '2001:db8::1', family: 6 }, connection: { httpVersion, alpn, source } });
  const active = { isSecureContext: true, crypto: webcrypto, navigator: { userActivation: { isActive: true } } };

  test('HTTP evidence must be bound to the challenge and the observed connection', () => {
    assert.equal(helpers.sampleResult(sample('HTTP/3', 'h3'), token).status, 'confirmed-h3');
    assert.equal(helpers.sampleResult(sample('HTTP/2.0', 'h2'), token).status, 'confirmed-h2');
    assert.equal(helpers.sampleResult(sample('HTTP/1.1', null, 'direct'), token).status, 'confirmed-h1');
    for (const unconfirmed of [sample('HTTP/3', 'h2'), sample('HTTP/3', 'h3', 'quic-initial'),
      sample(null, 'h3'), sample('HTTP/1.1', null, 'origin-leg'), { ...sample('HTTP/3', 'h3'), challenge: 'other' }]) {
      assert.equal(helpers.sampleResult(unconfirmed, token).status, 'unknown');
    }
    assert.equal(helpers.sampleResult(sample('HTTP/3', 'h3'), token).peer.ip, '2001:db8::1');
    assert.equal(helpers.sampleResult(sample('HTTP/2', 'h2', 'origin-leg'), token).reason, 'origin-leg');
  });

  const ingress = { source: 'trusted-edge', httpVersion: 'HTTP/2.0', tlsAlpn: 'h2' };
  const normalNav = { nextHopProtocol: 'h2', encodedBodySize: 2400, decodedBodySize: 9000, responseEnd: 50 };
  const navigation = (entry = normalNav, connection = ingress) => makeLab({ performance: { getEntriesByType(type) {
    assert.equal(type, 'navigation'); return entry ? [entry] : [];
  } } }).api.navigation(connection);

  test('original navigation compares observed protocol families without conflating hops or cache', () => {
    assert.equal(navigation().comparison, 'same');
    assert.equal(navigation({ ...normalNav, nextHopProtocol: 'http/1.0' }, { source: 'direct', httpVersion: 'HTTP/1.1' }).comparison, 'same');
    assert.equal(navigation({ ...normalNav, nextHopProtocol: 'h3-29' }).comparison, 'different');
    assert.equal(navigation(normalNav, { ...ingress, source: 'origin-leg' }).comparison, 'origin-leg');
    for (const [entry, connection] of [
      [null, ingress], [{ ...normalNav, nextHopProtocol: '' }, ingress],
      [normalNav, { ...ingress, tlsAlpn: 'h3' }], [normalNav, { ...ingress, tlsAlpn: 'h2c' }], [normalNav, { ...ingress, source: 'unknown' }],
      [{ ...normalNav, workerStart: 4 }, ingress], [{ ...normalNav, deliveryType: 'cache' }, ingress],
      [{ ...normalNav, transferSize: 0 }, ingress], [normalNav, null]
    ]) assert.equal(navigation(entry, connection).comparison, 'unknown');
    assert.equal(makeLab({ performance: { getEntriesByType() { throw new Error('unavailable'); } } }).api.navigation(ingress).comparison, 'unknown');
  });

  test('body measurement needs two exposed sizes on a completed nonempty navigation', () => {
    for (const encodedBytes of [2400, 9000, 9300]) {
      const measured = navigation({ ...normalNav, encodedBodySize: encodedBytes,
        get name() { throw new Error('navigation URL must stay unread'); } });
      assert.deepEqual(measured.body, { encodedBytes, decodedBytes: 9000 });
    }
    for (const unavailable of [null, { ...normalNav, responseEnd: 0 }, { ...normalNav, encodedBodySize: 0 },
      { ...normalNav, decodedBodySize: -1 }, { ...normalNav, decodedBodySize: undefined },
      { ...normalNav, encodedBodySize: NaN }]) assert.equal(navigation(unavailable).body, null);
  });

  test('route uses one fresh challenge and an anonymous no-store, no-redirect GET', async () => {
    const calls = [];
    const lab = makeLab({ ...active, fetch: async (url, options) => {
      calls.push({ url, options });
      return { ok: true, json: async () => ({ ...sample('HTTP/2', 'h2'), challenge: new URL(url).searchParams.get('challenge') }) };
    } }).api;
    assert.equal((await lab.route('https://probe.example.com/api/who/visibility/sample')).status, 'confirmed-h2');
    assert.equal((await lab.route('http://127.0.0.1:8000/who/api/who/visibility/sample')).status, 'confirmed-h2');
    assert.equal(calls.length, 2);
    const challenges = calls.map(({ url, options }) => {
      const { searchParams } = new URL(url);
      assert.deepEqual([...searchParams.keys()], ['challenge']);
      assert.match(searchParams.get('challenge'), /^[0-9a-f]{32}$/);
      assert.equal(options.credentials, 'omit');
      assert.equal(options.referrerPolicy, 'no-referrer');
      assert.equal(options.cache, 'no-store');
      assert.equal(options.redirect, 'error');
      return searchParams.get('challenge');
    });
    assert.notEqual(challenges[0], challenges[1]);
  });

  test('unsafe or non-sample URL is not requested and a hung body is aborted', async () => {
    let calls = 0, signal;
    const lab = makeLab({ ...active, fetch: async (url, opts) => {
      calls++; signal = opts.signal;
      return { ok: true, json: () => new Promise(() => {}) };
    } }).api;
    for (const url of ['http://example.com/api/who/visibility/sample', '//localhost/api/who/visibility/sample',
      'https://user:p@example.com/api/who/visibility/sample', 'https://example.com/',
      'https://example.com/api/who/visibility/sample?track=1', 'https://example.com/api/who/visibility/sample#id']) {
      assert.equal((await lab.route(url)).reason, 'invalid-probe-url');
    }
    assert.equal(calls, 0);
    assert.deepEqual(await lab.route('http://localhost/api/who/visibility/sample', { timeoutMs: 60 }), { status: 'unknown', reason: 'timeout' });
    assert.equal(signal.aborted, true);
  });

  test('different same-TLD sites are supported; subdomains and ambiguous suffixes are not cross-site evidence', () => {
    const endpoints = (...urls) => urls.map(helpers.endpoint);
    assert.equal(helpers.distinctSites(...endpoints('https://www.example.com', 'https://other.com', 'https://frames.test')), true);
    assert.equal(helpers.distinctSites(...endpoints('https://www.example.com', 'https://b.example.com:8443', 'https://frames.test')), false);
    assert.equal(helpers.distinctSites(...endpoints('https://a.example.co.uk', 'https://b.other.co.uk', 'https://frames.test')), false);
    assert.equal(helpers.distinctSites(...endpoints('https://a.example.com', 'https://b.other.com', 'https://frames.other.com')), false);
    assert.equal(helpers.distinctSites(...endpoints('http://localhost:8001', 'http://127.0.0.1:8002', 'http://[::1]:8003')), true);
  });

  test('storage popup is not opened without activation or verified site boundaries', async () => {
    const win = { ...active, location: new URL('https://a.example.com'), open: () => assert.fail('must not open') };
    win.top = win;
    const config = { peerURL: 'https://b.other.com', frameURL: 'https://f.other.com/frame' };
    assert.equal((await makeLab(win).api.storage(config)).reason, 'site-boundaries-unverified');
    const inactive = { ...win, navigator: { userActivation: { isActive: false } } };
    inactive.top = inactive;
    assert.equal((await makeLab(inactive).api.storage({ ...config, frameURL: 'https://frames.example.org' })).reason, 'user-activation-required');
  });

  test('storage messages bind exact source, origin, phase and nonce', () => {
    const source = {}, origin = 'https://frame.example.com';
    const event = { source, origin, data: { protocol: 'who-visibility-storage/v1', type: 'frame-result', nonce: token } };
    const accepts = x => helpers.authentic(x, source, origin, 'frame-result', token);
    assert.equal(accepts(event), true);
    for (const bad of [{ ...event, source: {} }, { ...event, origin: 'https://evil.example.com' },
      { ...event, data: { ...event.data, type: 'frame-clean' } }, { ...event, data: { ...event.data, nonce: 'b'.repeat(32) } }]) {
      assert.equal(accepts(bad), false);
    }
  });

  test('storage isolation requires both write/read controls and retained A data', () => {
    const cleaned = { cleaned: true, retained: true };
    const classify = (a, control, observed, aCleanup = cleaned, bCleanup = cleaned) =>
      helpers.mediaStatus(a, { control, observed }, aCleanup, bCleanup);
    assert.equal(classify('ok', 'ok', 'absent'), 'partitioned');
    assert.equal(classify('ok', 'ok', 'present'), 'shared');
    assert.equal(classify('ok', 'blocked', 'absent'), 'blocked');
    assert.equal(classify('inconclusive', 'ok', 'absent'), 'inconclusive');
    assert.equal(classify('ok', 'ok', 'absent', { cleaned: true, retained: false }), 'inconclusive');
    assert.equal(classify('ok', 'ok', 'other'), 'inconclusive');
    assert.equal(classify('ok', 'ok', 'present', cleaned, { cleaned: false }), 'inconclusive');
  });

  test('storage attempts cleanup after post-write readback is denied', async () => {
    const origin = new URL('https://frames.test/frame');
    let marker = null, removes = 0, cookie = '';
    const denied = () => new DOMException('storage unavailable', 'SecurityError');
    const storageWin = {
      location: origin, history: { replaceState(_data, _title, path) { origin.pathname = path; } },
      document: {
        get cookie() { return cookie; },
        set cookie(value) { cookie = value.includes('Max-Age=0;') ? '' : value.split(';')[0]; }
      },
      localStorage: {
        getItem() { if (marker) throw denied(); return null; },
        setItem(_key, value) { marker = value; },
        removeItem() { removes++; marker = null; }
      },
      get indexedDB() { throw denied(); }
    };
    const session = makeLab(storageWin).helpers.runInFrame('a', token, Date.now() + 2000);
    const sample = await session.sample;
    assert.equal(sample.controls.cookie, 'ok');
    assert.equal(sample.controls.localStorage, 'blocked');
    assert.ok(marker && cookie);
    const cleanup = await session.clean(true);
    assert.deepEqual(cleanup.cookie, { retained: true, cleaned: true });
    assert.equal(cleanup.localStorage.cleaned, false); // Removed, but readback could not be verified.
    assert.equal(marker, null);
    assert.equal(removes, 1);
    assert.equal(cookie, '');
  });

  test('TURN configuration admits no STUN, userinfo, or unrelated URL options', () => {
    const validate = urls => helpers.turnConfig({ urls, username: 'short-lived:user', credential: 'ephemeral-fixture-secret' });
    const relay = ['turn:relay.example.com:3478?transport=udp', 'turns:[2001:db8::1]:5349?transport=tcp'];
    assert.deepEqual(validate(relay).urls, relay);
    for (const invalid of ['stun:relay.example.com', 'turn:user@relay.example.com', 'turn://relay.example.com',
      'turn:relay.example.com?transport=tcp&next=x', 'turn:relay.example.com:65536', 'turns:relay.example.com?transport=udp']) {
      assert.equal(validate(invalid), null);
    }
    assert.equal(helpers.turnConfig({ urls: relay, username: '', credential: '' }), null);
  });

  function relayStats() {
    return new Map(Object.entries({
      t: { type: 'transport', selectedCandidatePairId: 'selected' },
      nominated: { type: 'candidate-pair', state: 'succeeded', nominated: true },
      selected: { type: 'candidate-pair', state: 'succeeded', localCandidateId: 'l', remoteCandidateId: 'r', currentRoundTripTime: 0.053 },
      l: { type: 'local-candidate', protocol: 'udp', relayProtocol: 'tls', candidateType: 'relay', address: '203.0.113.9' },
      r: { type: 'remote-candidate', protocol: 'udp', candidateType: 'relay', address: 'not-an-ip.local' }
    }));
  }

  test('RTC stats use the selected pair, do not guess candidate addresses, and report RTT in ms', () => {
    const stats = relayStats();
    const result = helpers.selectedPair(stats);
    assert.equal(result.local.ip, '203.0.113.9');
    assert.equal(result.local.relayProtocol, 'tls');
    assert.equal(result.remote.ip, null);
    assert.equal(result.rttMs, 53);
    stats.delete('t');
    assert.equal(helpers.selectedPair(stats), null);
  });

  function rtcFixture({ echo = 'ok', stallStats = false, nonRelay = false } = {}) {
    const peers = [], channels = [], added = [];
    const emit = (target, type, args) => target.dispatchEvent(Object.assign(new Event(type), args));
    class Channel extends EventTarget {
      constructor(label) { super(); this.label = label; channels.push(this); }
      send(data) {
        if (this === channels[1] && echo === 'missing') return;
        const target = this === channels[0] ? channels[1] : channels[0];
        queueMicrotask(() => emit(target, 'message', { data: this === channels[1] && echo === 'wrong' ? 'not-echo' : data }));
      }
      close() { this.closed = true; }
    }
    class Peer extends EventTarget {
      constructor(config) { super(); this.config = config; peers.push(this); }
      createDataChannel(label) { return new Channel(label); }
      async createOffer() { return { type: 'offer' }; }
      async createAnswer() { return { type: 'answer' }; }
      async setLocalDescription() {
        emit(this, 'icecandidate', { candidate: { type: 'host' } });
        emit(this, 'icecandidate', { candidate: { type: 'relay' } });
      }
      async setRemoteDescription(desc) {
        this.remoteDescription = desc;
        if (desc.type === 'answer') {
          emit(peers[1], 'datachannel', { channel: new Channel('who-visibility') });
          emit(channels[0], 'open', {});
        }
      }
      async addIceCandidate(candidate) { added.push(candidate); }
      getStats() {
        if (stallStats) return new Promise(() => {});
        const stats = relayStats();
        if (nonRelay) stats.get('l').candidateType = 'host';
        return Promise.resolve(stats);
      }
      close() { this.closed = true; }
    }
    return { lab: makeLab({ ...active, RTCPeerConnection: Peer }).api, peers, channels, added };
  }
  const rtcConfig = { urls: 'turn:relay.example.com', username: 'short-lived:user', credential: 'temporary', timeoutMs: 70 };
  test('RTC needs a matching nonce echo, filters non-relay ICE, and closes every resource', async () => {
    const { lab, peers, channels, added } = rtcFixture();
    const result = await lab.rtc(rtcConfig);
    assert.equal(result.status, 'connected');
    assert.equal(result.selected.b.rttMs, 53);
    assert.ok(peers.every(peer => peer.config.iceTransportPolicy === 'relay' && peer.closed));
    assert.ok(channels.every(channel => channel.closed));
    assert.deepEqual(added.map(x => x.type), ['relay', 'relay']);
  });
  test('contradictory RTC stats do not disclose non-relay addresses', async () => {
    const { lab } = rtcFixture({ nonRelay: true });
    assert.deepEqual(await lab.rtc(rtcConfig), { status: 'inconclusive', reason: 'unexpected-candidate' });
  });
  test('wrong RTC echo is inconclusive and a hung stats call does not erase a confirmed echo', async () => {
    const wrong = rtcFixture({ echo: 'wrong' });
    assert.deepEqual(await wrong.lab.rtc(rtcConfig), { status: 'inconclusive', reason: 'timeout' });
    assert.ok(wrong.peers.concat(wrong.channels).every(resource => resource.closed));
    const noStats = rtcFixture({ stallStats: true });
    assert.deepEqual(await noStats.lab.rtc(rtcConfig), { status: 'connected', reason: 'stats-unavailable', selected: { a: null, b: null } });
    assert.ok(noStats.peers.concat(noStats.channels).every(resource => resource.closed));
  });
}

async function startFixture() {
  const { createServer } = require('node:http');
  const { readFileSync } = require('node:fs');
  const { resolve } = require('node:path');
  const staticFile = name => readFileSync(resolve(__dirname, '../static', name), 'utf8');
  const bridge = staticFile('visibility-frame.html');
  const lab = staticFile('visibility-lab.js');
  const requests = [];
  const origins = {};
  const servers = [];
  const listen = async (role, bind, hostname) => {
    const server = createServer((req, res) => {
      const path = new URL(req.url, origins[role]).pathname;
      const send = (type, body, status = 200) => {
        res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store',
          ...(role === 'b' ? { 'Access-Control-Allow-Origin': origins.a } : {}) });
        res.end(body);
      };
      if (path === '/history') return send('application/json', JSON.stringify(requests));
      requests.push({ role, path, hadReferrer: !!req.headers.referer, hadCookie: !!req.headers.cookie, site: req.headers['sec-fetch-site'] ?? null });
      if (path === '/visibility-lab.js') return send('application/javascript', lab);
      if (path === '/api/who/visibility/sample' && role === 'b') {
        return send('application/json', JSON.stringify({ ok: true, challenge: new URL(req.url, origins.b).searchParams.get('challenge'),
          peer: { ip: req.socket.remoteAddress, family: 4 }, connection: { httpVersion: `HTTP/${req.httpVersion}`, alpn: null, source: 'direct' } }));
      }
      if (path === '/visibility-frame.html' && role !== 'a') {
        return send('text/html', bridge.replace('data-visibility-a-origin=""', `data-visibility-a-origin="${origins.a}"`)
          .replace('data-visibility-b-origin=""', `data-visibility-b-origin="${origins.b}"`)
          .replace('data-visibility-frame-url=""', `data-visibility-frame-url="${origins.frame}/visibility-frame.html"`));
      }
      if (path !== '/' || role !== 'a') return send('text/plain', 'not found', 404);
      return send('text/html', `<!doctype html><title>Local visibility fixture</title><link rel="icon" href="data:,">
<script src="/visibility-lab.js"></script><button id="route">route</button><button id="storage">storage</button><pre id="result"></pre>
<script>
const lab = window.WhoVisibilityLab;
const run = f => async () => { document.querySelector('#result').textContent = JSON.stringify(await f()); };
document.querySelector('#route').onclick = run(() => lab.route(${JSON.stringify(origins.b + '/api/who/visibility/sample')}));
document.querySelector('#storage').onclick = run(() => lab.storage(${JSON.stringify({ peerURL: origins.b + '/visibility-frame.html', frameURL: origins.frame + '/visibility-frame.html' })}));
</script>`);
    });
    servers.push(server);
    await new Promise((done, fail) => { server.once('error', fail); server.listen(0, bind, done); });
    origins[role] = `http://${hostname}:${server.address().port}`;
  };
  try {
    await listen('a', '127.0.0.1', 'localhost');
    await listen('b', '127.0.0.1', '127.0.0.1');
    await listen('frame', '::1', '[::1]');
    console.log(JSON.stringify(origins));
  } catch (err) {
    servers.forEach(server => server.close());
    throw err;
  }
}
