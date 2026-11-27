const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

// Load the real browser entry point without starting its network probes.
// Only the browser readings and DOM are fixtures; the scoring and probe code run unchanged.
const app = fs.readFileSync(path.join(__dirname, "../static/app.js"), "utf8");
const instrumented = app.replace(/\}\)\(\);\s*$/, `
  globalThis.tests = {
    readWorker: probeWorkerRealm,
    readIframe: probeLiesAndIframe,
    readShared: probeSwRealm,
    readCpu: probeCpuArch,
    readPopup: probePopupBlocker,
    readHardware: probeAsyncHardware,
    readMqScreen: probeMqScreen,
    readFontLocal: probeFontLocal,
    readHeaders: probeHeaderForensics,
    readDns: probeDns,
    readRoutes: probeQuicAndExits,
    readRtc: probeWebrtc,
    readV6: probeV6Mac,
    readNav: () => probeNavigationTiming(),
    readHighEntropy: probeHighEntropyHints,
    detectDevice,
    detectBrowser,
    applyIntel: applyIntelToProbes,
    updateUdp: updateUdpRttProbe,
    setIceTiming: value => { R.stunRttMs = value; },
    check: evaluateAllChecks,
    score: () => { renderChecksAndScore(); return R.score; },
    read: id => R.values[id],
    setState: state => { R = state; },
    getState: () => R,
    scenarios: computeScenarios,
    compare: (id, result) => getVisualConflict(id, result),
  };
})();`);
assert.notEqual(instrumented, app, "browser closure to exercise was not found");

function harness({ mainMemory, workerMemory, iframeMemory, mainPlatform = "MacIntel", userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", cssSupports, shared, readings = {}, state = {}, fetch, performance, peer } = {}) {
  const navigator = Object.create({ userAgent, platform: mainPlatform, language: "en-US", languages: ["en-US"], hardwareConcurrency: 8, deviceMemory: mainMemory });
  const screen = Object.create({ width: 1440, height: 900 });
  const iframe = {
    style: {}, setAttribute() {}, remove() {},
    contentWindow: { navigator: Object.create(navigator, { deviceMemory: { value: iframeMemory } }), screen, Intl, Date }
  };
  const worker = {
    ua: userAgent, plat: navigator.platform, langs: "en-US", hc: 8,
    mem: workerMemory, tz: Intl.DateTimeFormat().resolvedOptions().timeZone, ...readings,
  };
  class Worker {
    set onmessage(callback) { queueMicrotask(() => callback({ data: worker })); }
    terminate() {}
  }
  const nodes = Object.fromEntries([
    "sceneBadge", "topGiveaway", "scoreSub", "issueCount", "cntBad", "cntWarn", "cntOk", "splitSummaryBadge", "tabRoutesBadge",
  ].map(id => [`#${id}`, {}]));
  const document = {
    querySelector: key => nodes[key] || null, querySelectorAll: () => [], addEventListener() {},
    createElement: tag => { assert.equal(tag, "iframe"); return iframe; }, body: { appendChild() {} }
  };
  const sandbox = {
    document, navigator, screen, window: { Worker, Blob, RTCPeerConnection: peer }, Worker, Blob, URL, Intl,
    performance: performance || { getEntriesByType: () => [], now: () => 20 }, fetch, AbortSignal, crypto: require("node:crypto").webcrypto, clearTimeout,
    CSS: cssSupports ? { supports: cssSupports } : undefined,
    location: { hostname: "localhost", href: "http://localhost/", search: "" },
    setTimeout() {}, // the fake worker sends its reply in a microtask; no timeout needs to fire
  };
  if (shared) sandbox.SharedWorker = class {
    port = { start() {}, close() {}, postMessage() { this.onmessage({ data: shared }); } };
  };
  vm.runInNewContext(instrumented, sandbox, { filename: "static/app.js" });
  sandbox.tests.node = id => nodes[`#${id}`];
  sandbox.tests.setState({ finished: true, values: {}, ...state });
  return sandbox.tests;
}

test("routing needs two independent, valid observations, not a copied or malformed exit", async () => {
  const self = "8.8.8.8";
  for (const [foreign, v4, v6, measured] of [
    [null, "<html>login required</html>", "Error: request failed", false],
    [null, "999.42.1.5", "2606:4700:::1111", false],
    [null, "2606:4700:4700::1111", self, false],
    [null, self, "", true],
    [self, "", "", true],
  ]) {
    const h = harness({ state: { ip: self, ipCC: "US", exits: { ex_self: { ip: self, cc: "US" } }, isSharedView: true }, fetch: async url => ({
      ok: true, json: async () => url.includes("api.ip.sb") ? { ip: foreign, country_code: "US" } : {},
      text: async () => url.includes("ipv4.icanhazip") ? v4 : url.includes("ipv6.icanhazip") ? v6 : "",
    }) });
    await h.readRoutes();
    assert.equal(h.check().split.level, measured ? "ok" : "info");
    if (!measured) {
      assert.deepEqual({ ...h.getState().stack }, { v4: "", v6: "" });
      assert.match(h.node("splitSummaryBadge").textContent, /不足/);
      assert.match(h.node("tabRoutesBadge").textContent, /不足/);
    }
  }
  const missingSelf = harness({ state: { srvFailed: true, isSharedView: true }, fetch: async url => ({
    ok: true, json: async () => url.includes("api.ip.sb") ? { ip: self, country_code: "US" } : {}, text: async () => "",
  }) });
  await missingSelf.readRoutes();
  assert.equal(missingSelf.getState().exits.ex_intl.ip, self);
  assert.ok(!missingSelf.getState().ip && !missingSelf.getState().exits.ex_self);
  assert.equal(missingSelf.check().split.level, "info");
  const ipv6 = harness({ state: { ip: "2606:4700:4700::1111", exits: { ex_self: { ip: "2606:4700:4700::1111" } } }, fetch: async url => ({
    ok: true, json: async () => ({}), text: async () => url.includes("ipv6.icanhazip") ? "2606:4700:4700:0000:0000:0000:0000:1111\n" : "",
  }) });
  await ipv6.readRoutes();
  assert.equal(ipv6.getState().stack.v6, ipv6.getState().ip);
  assert.equal(ipv6.check().split.level, "ok");
});

test("DNS comparison separates missing geography, observed ECS and failed remeasurement", async () => {
  const resolver = { dns: { ip: "1.1.1.1", geo: "China - Example Resolver" } };
  let responses = [resolver, resolver];
  const h = harness({ state: { ip: "8.8.8.8" }, fetch: async () => ({ ok: true, json: async () => responses.shift() }) });
  await h.readDns();
  assert.equal(h.check().dns.level, "info");
  assert.doesNotMatch(h.read("ecs"), /同国|DoH|泄漏/);
  h.setState({ ...h.getState(), ipCC: "CN" });
  responses = [resolver, { ...resolver, edns: { ip: "8.8.8.0/24" } }];
  await h.readDns();
  assert.match(h.check().dns.summary, /ECS.*8\.8\.8\.0\/24/);
  assert.doesNotMatch(h.check().dns.summary, /无 ECS|异网段/);
  responses = [resolver, { dns: { ip: "9.9.9.9", geo: "Singapore - Second Resolver" } }];
  await h.readDns();
  assert.equal(h.check().dns.level, "warn");
  assert.match(h.compare("dns", h.check().dns).left, /SG/);
  responses = [resolver, { ...resolver, edns: { ip: "0.0.0.0/0" } }];
  await h.readDns();
  assert.equal(h.check().dns.level, "ok");
  assert.ok(!h.getState().ecsIp);
  responses = [resolver, { ...resolver, edns: { ip: "8.8.8.0/80" } }];
  await h.readDns();
  assert.equal(h.check().dns.level, "info");
  responses = [{ dns: {} }, null];
  await h.readDns();
  assert.equal(h.check().dns.level, "info");
  assert.ok(!h.getState().dnsIp && !h.getState().ecsIp);
});

test("only UDP server-reflexive ICE candidates contribute to the STUN exit and timing", async () => {
  const candidates = [
    "candidate:123456 1 udp 12345 8.8.8.8 12345 typ host",
    "candidate:123457 1 udp 12345 8.8.4.4 12345 typ relay",
    "candidate:123458 1 udp 12345 1.1.1.1 12345 typ prflx",
    "candidate:123459 1 tcp 12345 1.0.0.1 12345 typ srflx tcptype passive",
    "candidate:123460 1 udp 12345 9.9.9.9 12345 typ srflx raddr 0.0.0.0 rport 0",
    "candidate:123461 1 udp 12345 bbccdeff.local 12345 typ host",
  ];
  const peer = class {
    createDataChannel() {} async createOffer() { return {}; } close() {}
    async setLocalDescription() {
      for (const candidate of candidates) this.onicecandidate({ candidate: { candidate } });
      this.onicecandidate({ candidate: null });
    }
  };
  const h = harness({ peer, state: { ip: "9.9.9.9" } });
  await h.readRtc();
  assert.deepEqual([...h.getState().rtc], ["9.9.9.9"]);
  assert.deepEqual([...h.getState().lan], ["bbccdeff.local"]);
  assert.equal(h.check().webrtc.level, "ok");
  candidates.splice(4);
  await h.readRtc();
  assert.equal(h.getState().stunRttMs, null);
  assert.equal(h.check().webrtc.level, "info");
  assert.match(h.read("lan"), /未.*候选/);
  const denied = harness({ peer: class { constructor() { throw Object.assign(new Error(), { name: "NotAllowedError" }); } } });
  await denied.readRtc();
  assert.match(denied.read("webrtc"), /NotAllowedError/);
  assert.match(denied.read("lan"), /NotAllowedError/);
  assert.equal(denied.check().webrtc.level, "info");
  const pattern = harness({ state: { rtcDone: true, rtc: [], ip: "2606:4700::0211:22ff:fe33:4455" } });
  pattern.readV6();
  assert.equal(pattern.getState().v6mac, "00:11:22:33:44:55");
  assert.equal(pattern.check().webrtc.level, "info");
  assert.match(pattern.read("v6mac"), /不能确认/);
});

test("navigation metrics never invent a protocol, TLS handshake, or negative duration", () => {
  const nav = { nextHopProtocol: "", requestStart: 50, responseStart: 0, secureConnectionStart: 0, connectEnd: 0 };
  const h = harness({ performance: { getEntriesByType: () => [nav] } });
  h.readNav();
  assert.doesNotMatch(h.read("perf_nav"), /h2|\d+ms/);
  Object.assign(nav, { nextHopProtocol: "h3", responseStart: 56, secureConnectionStart: 8, connectEnd: 10 });
  h.readNav();
  assert.match(h.read("perf_nav"), /h3.*2\s*ms.*6\s*ms/);
  Object.assign(nav, { connectEnd: 8, responseStart: 50 });
  h.readNav();
  assert.match(h.read("perf_nav"), /TLS耗时 未测出.*首字节 0ms/);
});

test("STUN comparison does not score cross-family differences against this site's HTTP exit", () => {
  const ipv6 = "2606:4700:4700::1111";
  for (const [ip, candidate] of [["1.1.1.1", ipv6], [ipv6, "1.1.1.1"]]) {
    const state = { rtcDone: true, ip, rtc: [candidate] };
    const page = harness({ state });
    assert.equal(page.check().webrtc.level, "info");
    assert.match(page.check().webrtc.summary, /缺少同地址族/);
    page.setState({ ...state, rtc: [candidate, ip] });
    const mixed = page.check().webrtc;
    assert.equal(mixed.level, "ok");
    assert.match(mixed.summary, /另一地址族未核对/);
  }
});

for (const [name, mainMemory, workerMemory] of [
  ["on the page", undefined, 8],
  ["in the worker", 8, undefined],
  ["in both contexts", undefined, undefined],
]) {
  test(`unavailable memory ${name} is not a conflict or a successful comparison`, async () => {
    const h = harness({ mainMemory, workerMemory });
    await h.readWorker();
    assert.notEqual(h.check().fpb.level, "bad");
    assert.match(h.read("worker"), /内存/);
    assert.doesNotMatch(h.read("worker"), /完全一致/);
  });
}

test("two different memory values still report a direct mismatch", async () => {
  const h = harness({ mainMemory: 4, workerMemory: 8 });
  await h.readWorker();
  assert.equal(h.check().fpb.level, "bad");
  assert.match(h.read("worker"), /不一致.*内存/);
});

test("a worker response with no comparable fields is not a pass", async () => {
  const h = harness({ readings: { ua: "", plat: "", langs: "", hc: null, mem: null, tz: "" } });
  await h.readWorker();
  assert.match(h.read("worker"), /没有可.*核对|无可.*核对/);
});

test("missing iframe memory is unavailable, but two concrete values can disagree", () => {
  const hidden = harness({ iframeMemory: 8 });
  hidden.readIframe();
  assert.match(hidden.read("iframe"), /未核对：deviceMemory/);
  assert.notEqual(hidden.check().tamper.level, "bad");
  const mismatch = harness({ mainMemory: 4, iframeMemory: 8 });
  mismatch.readIframe();
  assert.match(mismatch.read("iframe"), /读数不符：deviceMemory/);
  assert.equal(mismatch.check().tamper.level, "bad");
});

test("a platform visible only in SharedWorker is not a cross-realm conflict", async () => {
  const h = harness({ mainPlatform: "", shared: { plat: "MacIntel", hc: 8, lang: "en-US" } });
  await h.readShared();
  assert.notEqual(h.check().fpb.level, "bad");
  assert.match(h.read("swrealm"), /已核对 2 项.*未核对/);
});

test("a NaN architecture discrepancy is informational, not an issue", () => {
  // Select the opposite Client Hints value for this JS engine's actual sample.
  const f = new Float32Array(1);
  f[0] = Infinity;
  f[0] = f[0] - f[0];
  const detected = new Uint8Array(f.buffer)[3] === 255 ? "x86" : "arm";
  const state = { finished: true, values: {}, hi: { architecture: detected === "x86" ? "arm" : "x86" } };
  const h = harness({ state });
  const before = h.score();
  h.readCpu();
  assert.equal(h.check().fpb.level, "info");
  assert.match(h.read("cpuarch"), /架构参考|仅供参考|架构推测/);
  assert.equal(h.score(), before);
});

test("an explicit Linux platform and Apple Metal renderer remain a real inconsistency", () => {
  const h = harness({ state: { dev: { os: "Linux" }, gpuRaw: "ANGLE (Apple, ANGLE Metal Renderer: Apple M5)" } });
  const finding = h.check().fpb;
  assert.equal(finding.level, "bad");
  assert.match(finding.summary, /Apple.*Linux/);
  assert.doesNotMatch(finding.summary, /虚拟机硬伤/);
});

test("955 ms HTTP-only is visible without classifying or scoring it as multi-hop", () => {
  const state = { finished: true, values: {}, latDone: true, httpRtt: 955, srvTcpRtt: null };
  for (const geo of [false, true]) {
    const h = harness({ state: geo ? { ...state, ipLat: 13.75, ipLon: 100.5, srvCoords: [35.7, 139.7] } : state });
    const verdict = h.check().rtt;
    assert.equal(verdict.level, "info");
    assert.match(verdict.summary, /955 ms.*延迟偏高.*未.*握手/);
    assert.equal(h.compare("rtt", verdict).single, "延迟偏高");
    const highScore = h.score();
    h.setState({ ...state, httpRtt: 46 });
    assert.equal(h.score(), highScore);
    h.setState({ ...state, httpRtt: 46, srvTcpRtt: 42 });
    assert.equal(h.score(), highScore);
  }
});

test("a fast ICE candidate cannot convert HTTP-only latency into a UDP bypass warning", () => {
  const h = harness({ state: { latDone: true, httpRtt: 955, rtcDone: true } });
  h.setIceTiming(22);
  h.updateUdp();
  assert.match(h.read("udprtt"), /首个公网 ICE 候选 22 ms/);
  assert.equal(h.check().rtt.level, "info");
});

test("a measured TCP vs HTTP gap is still reported, without claiming an exact route", () => {
  const h = harness({ state: { latDone: true, httpRtt: 450, srvTcpRtt: 45 } });
  const verdict = h.check().rtt;
  assert.equal(verdict.level, "bad");
  assert.match(verdict.summary, /450 ms.*45 ms|45 ms.*450 ms/);
  assert.doesNotMatch(verdict.summary, /抓获|实锤/);
});

test("partial-coverage 5G IPv4 and IPv6 intel with sufficient sources pass reputation without false timeout retest", () => {
  const cleanBase = {
    finished: true,
    values: {},
    ip: "9.9.9.42",
    ipCC: "US",
    tz: "America/New_York",
    langs: ["en-US"],
    dnsCC: "US",
    exitsDone: true,
    exits: { ex_self: { ip: "9.9.9.42", cc: "US" }, ex_intl: { ip: "9.9.9.42", cc: "US" } },
    latDone: true,
    httpRtt: 38,
    srvTcpRtt: 34,
    rtcDone: true,
    rtc: ["9.9.9.42"],
    netKind: "mobile",
    asn: "AS7922",
    org: "Example Wireless",
    fontRast: { engine: "CoreText", rgbRatio: 0 },
    scrollbarW: 0,
    cpuBench: { stealRatio: 1.1, simdOk: true },
    hwCodecs: 4,
    dev: { os: "iOS" },
    osLabel: "iOS 18.7",
  };

  // 5G IPv4 where Shodan returned 404 (unseen -> uncertain: true) and 2 free APIs timed out (41/46 known)
  const h4 = harness({
    state: {
      ...cleanBase,
      intel: {
        ok: true,
        ipVersion: 4,
        purity: { score: 99, grade: "S", uncertain: true, coverage: { known: 41, unknown: 5, notApplicable: 2, applicable: 46, ratio: 0.891 } },
        votes: { proxy: { of: 4, E: 0.02 }, hosting: { of: 5, E: 0.02 }, vpn: { of: 4, E: 0 }, tor: { of: 4, E: 0 } },
        dnsbl: { total: 11, listedCount: 0 },
        cidr: { hits: [], neighbours: { dirtyCount: 0, wholeBlockListed: [] } },
        tls443: { probed: false },
      },
    },
  });
  const rep4 = h4.check().reputation;
  assert.equal(rep4.level, "ok");
  assert.match(rep4.summary, /99\/100 \(S\).*覆盖 41\/46/);
  assert.equal(h4.score(), 100);
  assert.equal(h4.getState().grade, "A+");
  assert.equal(h4.getState().unverifiedCnt, 0);
  assert.doesNotMatch(h4.node("scoreSub").textContent, /超时|覆盖不足/);

  // 5G IPv6 where DNSBL/CIDR are not_applicable (13/17 known, uncertain: true)
  const h6 = harness({
    state: {
      ...cleanBase,
      ip: "2620:fe::42",
      rtc: ["2620:fe::42"],
      intel: {
        ok: true,
        ipVersion: 6,
        purity: { score: 93, grade: "A", uncertain: true, coverage: { known: 13, unknown: 4, notApplicable: 29, applicable: 17, ratio: 0.765 } },
        votes: { proxy: { of: 3, E: 0 }, hosting: { of: 4, E: 0 }, vpn: { of: 3, E: 0 }, tor: { of: 3, E: 0 } },
        dnsbl: { total: 0, listedCount: 0 },
        cidr: { hits: [], neighbours: { dirtyCount: 0, wholeBlockListed: [] } },
        tls443: { probed: false },
      },
    },
  });
  assert.equal(h6.check().reputation.level, "ok");
  assert.equal(h6.score(), 100);
  assert.equal(h6.getState().unverifiedCnt, 0);

  // Truly sparse upstream coverage keeps fail-closed uncertainty cap, without falsely blaming probe timeout
  const sparse = harness({
    state: {
      ...cleanBase,
      intel: {
        ok: true,
        ipVersion: 4,
        purity: { score: 92, grade: "A", uncertain: true, coverage: { known: 0, unknown: 44, notApplicable: 2, applicable: 44, ratio: 0 } },
        votes: { proxy: { of: 0, E: 0 }, hosting: { of: 0, E: 0 } },
        dnsbl: { total: 0, listedCount: 0 },
        cidr: { hits: [], neighbours: { dirtyCount: 0, wholeBlockListed: [] } },
        tls443: { probed: false },
      },
    },
  });
  assert.equal(sparse.check().reputation.level, "info");
  assert.equal(sparse.score(), 95);
  assert.equal(sparse.getState().grade, "A");
  assert.match(sparse.node("scoreSub").textContent, /覆盖不足/);
  assert.doesNotMatch(sparse.node("scoreSub").textContent, /超时/);

  // Real client-to-server /api/who/intel timeout still reports network probe timeout
  const timedOut = harness({ state: { ...cleanBase, intel: null } });
  assert.equal(timedOut.check().reputation.level, "info");
  timedOut.score();
  assert.match(timedOut.node("scoreSub").textContent, /网络探针超时/);
});

test("a single mail-only DNSBL hit on home broadband affects SMTP only, while abuse DNSBL hits remain bad", () => {
  const ispBase = {
    finished: true,
    values: {},
    ip: "9.9.9.42",
    ipCC: "TH",
    tz: "Asia/Bangkok",
    langs: ["th-TH"],
    dnsCC: "TH",
    exitsDone: true,
    exits: { ex_self: { ip: "9.9.9.42", cc: "TH" }, ex_intl: { ip: "9.9.9.42", cc: "TH" } },
    latDone: true,
    httpRtt: 28,
    srvTcpRtt: 26,
    rtcDone: true,
    rtc: ["9.9.9.42"],
    netKind: "isp",
    asn: "AS17552",
    org: "Example Broadband",
    fontRast: { engine: "FreeType", rgbRatio: 0.1 },
    scrollbarW: 15,
    cpuBench: { stealRatio: 1.1, simdOk: true },
    hwCodecs: 4,
    dev: { os: "Linux" },
    osLabel: "Linux",
  };

  const mailOnly = harness({
    state: {
      ...ispBase,
      intel: {
        ok: true,
        ipVersion: 4,
        consensus: { country: "TH", isNative: true },
        asnProfile: { inferred: { cls: "isp" } },
        purity: { score: 94, grade: "A", uncertain: true, coverage: { known: 37, unknown: 9, notApplicable: 2, applicable: 46, ratio: 0.804 } },
        votes: { proxy: { of: 4, E: 0 }, hosting: { of: 5, E: 0 }, vpn: { of: 4, E: 0 }, tor: { of: 4, E: 0 } },
        dnsbl: { total: 11, listedCount: 1, abuseCount: 0, mailCount: 1, listed: ["Barracuda"], abuseListed: [], mailListed: ["Barracuda"], droneProxy: false },
        cidr: { hits: [], neighbours: { dirtyCount: 0, wholeBlockListed: [] } },
        tls443: { probed: false },
      },
    },
  });
  const repMail = mailOnly.check().reputation;
  assert.equal(repMail.level, "ok");
  assert.match(repMail.summary, /Barracuda.*不影响常规网页访问/);
  assert.equal(mailOnly.score(), 100);
  const scMail = mailOnly.scenarios();
  assert.ok(scMail.ai.score >= 95 && scMail.streaming.score >= 95 && scMail.social.score >= 95 && scMail.captcha.score >= 95 && scMail.fintech.score >= 95);
  assert.ok(scMail.email.score < 50);

  const abuseHit = harness({
    state: {
      ...ispBase,
      intel: {
        ok: true,
        ipVersion: 4,
        consensus: { country: "TH", isNative: true },
        asnProfile: { inferred: { cls: "isp" } },
        purity: { score: 86, grade: "A", uncertain: false, coverage: { known: 46, unknown: 0, notApplicable: 2, applicable: 46, ratio: 1 } },
        votes: { proxy: { of: 4, E: 0.2 }, hosting: { of: 5, E: 0 }, vpn: { of: 4, E: 0 }, tor: { of: 4, E: 0 } },
        dnsbl: { total: 12, listedCount: 1, abuseCount: 1, mailCount: 0, listed: ["DroneBL"], abuseListed: ["DroneBL"], mailListed: [], droneProxy: false },
        cidr: { hits: [], neighbours: { dirtyCount: 0, wholeBlockListed: [] } },
        tls443: { probed: false },
      },
    },
  });
  const repAbuse = abuseHit.check().reputation;
  assert.equal(repAbuse.level, "bad");
  assert.equal(abuseHit.compare("reputation", repAbuse).single, "黑名单 1 家");
  const scAbuse = abuseHit.scenarios();
  assert.ok(scAbuse.captcha.score < 70 && scAbuse.social.score < 80);
});

test("automatic page probes never call window.open or Widevine DRM on Linux/Android", async () => {
  const drmCalls = [];
  const linuxAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";
  const navigator = {
    userAgent: linuxAgent,
    platform: "Linux x86_64",
    language: "en-US",
    languages: ["en-US"],
    hardwareConcurrency: 8,
    requestMediaKeySystemAccess: async keySystem => {
      drmCalls.push(keySystem);
      return {};
    },
  };
  const nodes = Object.fromEntries(["sceneBadge", "topGiveaway", "scoreSub", "issueCount", "cntBad", "cntWarn", "cntOk"].map(id => [`#${id}`, {}]));
  let windowOpenCalled = false;
  const win = {
    open: () => { windowOpenCalled = true; throw new Error("window.open must not run on load"); },
    matchMedia: () => ({ matches: false }),
  };
  const sandbox = {
    document: { querySelector: k => nodes[k] || null, querySelectorAll: () => [], addEventListener() {}, createElement: () => ({ style: {}, setAttribute() {}, remove() {} }), body: { appendChild() {} } },
    navigator,
    screen: { width: 1920, height: 1080 },
    window: win,
    URL,
    Intl,
    location: { hostname: "localhost", href: "http://localhost/", search: "" },
    setTimeout,
  };
  vm.runInNewContext(instrumented, sandbox, { filename: "static/app.js" });
  sandbox.tests.setState({ finished: true, values: {} });
  sandbox.tests.readPopup();
  await sandbox.tests.readHardware();
  assert.equal(windowOpenCalled, false);
  assert.equal(sandbox.tests.getState().popupDisabled, false);
  assert.deepEqual(drmCalls, ["org.w3.clearkey"]);
});

test("genuine Android phone with nav-bar height inset, PostScript font aliases, zh-Hans-CN and GMS-less ROM passes tamper with zero popups", async () => {
  const ua = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36";
  let fidoCalled = false, btCalled = false, widevineCalled = false;
  const navigator = {
    userAgent: ua,
    platform: "Linux armv81",
    language: "zh-Hans-CN",
    languages: ["zh-Hans-CN"],
    hardwareConcurrency: 8,
    bluetooth: { getAvailability: async () => { btCalled = true; return true; } },
    requestMediaKeySystemAccess: async ks => {
      if (ks !== "org.w3.clearkey") widevineCalled = true;
      return {};
    },
  };
  const matchMedia = q => {
    if (q === "(pointer: coarse)") return { matches: true };
    if (q === "(orientation: portrait)") return { matches: true };
    const mw = /^\(min-device-width:\s*(\d+)px\)$/.exec(q);
    if (mw) return { matches: Number(mw[1]) <= 360 };
    const mh = /^\(min-device-height:\s*(\d+)px\)$/.exec(q);
    if (mh) return { matches: Number(mh[1]) <= 770 }; // full 1080x2310 @ 3x panel height
    if (q.includes("resolution")) return { matches: false }; // simulate Android font-scale dppx shift
    return { matches: false };
  };
  class FontFace {
    constructor(_fam, src) { this.src = src; }
    async load() {
      // Android fonts.xml loads PostScript names without matching CSS family names in Canvas
      if (/NotoSansCJKsc-Regular|HelveticaNeue|Roboto/.test(this.src)) return this;
      throw new Error("not found");
    }
  }
  const nodes = Object.fromEntries(["sceneBadge", "topGiveaway", "scoreSub", "issueCount", "cntBad", "cntWarn", "cntOk"].map(id => [`#${id}`, {}]));
  const win = {
    innerWidth: 360,
    innerHeight: 660,
    devicePixelRatio: 3,
    matchMedia,
    PublicKeyCredential: { isUserVerifyingPlatformAuthenticatorAvailable: async () => { fidoCalled = true; return true; } },
    open: () => { throw new Error("popup forbidden"); },
  };
  const sandbox = {
    document: { querySelector: k => nodes[k] || null, querySelectorAll: () => [], addEventListener() {}, createElement: () => ({ style: {}, setAttribute() {}, remove() {} }), body: { appendChild() {} } },
    navigator,
    screen: { width: 360, height: 728 }, // 42px Android navigation bar subtracted
    window: win,
    FontFace,
    URL,
    Intl,
    location: { hostname: "localhost", href: "http://localhost/", search: "" },
    setTimeout,
  };
  vm.runInNewContext(instrumented, sandbox, { filename: "static/app.js" });
  sandbox.tests.setState({
    finished: true,
    values: {},
    dev: { os: "Android", osv: "9", kind: "phone", model: "Example-Phone" },
    br: { name: "Chrome", v: "138", inApp: false },
    engine: "V8",
    langs: ["zh-Hans-CN"],
    fonts: ["Roboto"],
    tzOff: 480,
    dateOff: 480,
    srv: {
      headers: {
        "user-agent": ua,
        "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
      },
      proxyHeaders: { names: [], xffHops: 0, via: "" },
    },
  });
  sandbox.tests.readPopup();
  sandbox.tests.readMqScreen();
  await sandbox.tests.readFontLocal();
  sandbox.tests.readHeaders();
  await sandbox.tests.readHardware();

  assert.equal(fidoCalled, false, "PublicKeyCredential must not be called on Android");
  assert.equal(btCalled, false, "bluetooth.getAvailability must not be called on Android");
  assert.equal(widevineCalled, false, "Widevine must not be called on Android");
  const checks = sandbox.tests.check();
  assert.equal(checks.tamper.level, "ok", checks.tamper.summary);
});

test("single-source dc tag on ISP-announced leased block reconciles to ISP + lease warning instead of contradicting scenarios", () => {
  const h = harness({
    state: {
      finished: true,
      values: {},
      ip: "9.9.9.42",
      ipCC: "US",
      netKind: "dc", // initial single-source GeoIP false positive
      asn: "AS5650",
      org: "Verizon Business",
    },
  });
  const intel = {
    ok: true,
    isSelfEgress: true,
    targetIp: "9.9.9.42",
    ipVersion: 4,
    consensus: { country: "US", isNative: true, asn: 5650, org: "Verizon Business" },
    votes: { hosting: { of: 5, yes: 2, E: 0.504 }, proxy: { of: 5, E: 0.222 }, vpn: { of: 4, E: 0 }, tor: { of: 3, E: 0 } },
    asnProfile: {
      inferred: { cls: "isp", conflict: null },
      lease: { leased: true, possible: false, confidence: 0.6, reasons: ["管理/滥用联系人命中 IP 租赁/托管平台 (PF IPV4 Borrower)"] },
    },
    purity: { score: 92, grade: "A", uncertain: false, coverage: { known: 46, unknown: 0, notApplicable: 2, applicable: 46, ratio: 1 } },
    dnsbl: { total: 12, listedCount: 0, abuseCount: 0, mailCount: 0, listed: [] },
    cidr: { hits: [], x4bDatacenter: false, x4bVpn: false, neighbours: { dirtyCount: 0, wholeBlockListed: [] } },
    tls443: { probed: false },
  };
  h.setState({ ...h.getState(), intel });
  h.applyIntel(intel);
  assert.equal(h.getState().netKind, "isp");
  const ck = h.check();
  assert.equal(ck.dc.level, "ok");
  assert.equal(ck.lease.level, "warn");
  assert.match(ck.lease.summary, /商业租赁/);
});

test("reverse handshake inflation (28ms HTTP vs 317ms SYN->ClientHello), local CF PoP RTT, and 3-way split-tunneling are caught", () => {
  // 1) 28 ms HTTP vs 317 ms SYN->ClientHello (SOCKS5/CONNECT two-stage handshake or clamped ResourceTiming)
  const hRev = harness({
    state: {
      finished: true,
      values: {},
      ip: "9.9.9.42",
      ipCC: "TH",
      netKind: "isp",
      dev: { os: "Linux" },
      latDone: true,
      httpRtt: 28,
      srvTcpRtt: 317,
    },
  });
  const rttRev = hRev.check().rtt;
  assert.equal(rttRev.level, "bad");
  assert.match(rttRev.summary, /317 ms/);
  assert.equal(hRev.compare("rtt", rttRev).left, "握手 317ms");

  // 2) Same-country local Cloudflare PoP (BKK in TH) warm RTT 215 ms reveals proxy hop even when server handshake looks close
  const hCf = harness({
    state: {
      finished: true,
      values: {},
      ip: "9.9.9.42",
      ipCC: "TH",
      netKind: "isp",
      dev: { os: "Linux" },
      latDone: true,
      httpRtt: 95,
      srvTcpRtt: 85,
      cfLocalColo: "BKK",
      cfLocalRtt: 215,
      exits: { ex_self: { ip: "9.9.9.42", cc: "TH" }, ex_cf: { ip: "9.9.9.42", cc: "TH", colo: "BKK" } },
    },
  });
  const rttCf = hCf.check().rtt;
  assert.equal(rttCf.level, "bad");
  assert.match(rttCf.summary, /BKK.*215 ms/);

  // 3) 3-way split-tunneling across Mainland streaming DIRECT + TH proxy + US AI rule / IPv6 stack
  const hSplit = harness({
    state: {
      finished: true,
      values: {},
      ip: "9.9.9.42",
      ipCC: "TH",
      netKind: "isp",
      exitsDone: true,
      exits: {
        ex_self: { ip: "9.9.9.42", cc: "TH", label: "泰国" },
        ex_cn: { ip: "203.0.113.10", cc: "CN", label: "中国 · ZheJiang · CMNET" },
        ex_cn_alt: { ip: "9.9.9.42", cc: "TH", label: "泰国" },
        ex_gpt: { ip: "198.51.100.88", cc: "US", label: "美国" },
      },
      stack: { v4: "9.9.9.42", v6: "2409:8a00::1" },
    },
  });
  const sp = hSplit.check().split;
  assert.equal(sp.level, "bad");
  assert.match(sp.summary, /203\.0\.113\.10.*3 个不同出口/);

  // 4) Overseas roaming SIM in Mainland China (same SG exit IP across all probes, even if a domestic geo DB mislabels CMI carrier as CN):
  //    split MUST pass (ok), while Asia/Shanghai vs Asia/Singapore (both UTC+8) stays a mild warn!
  const hRoam = harness({
    state: {
      finished: true,
      values: {},
      ip: "9.9.9.42",
      ipCC: "SG",
      ipTz: "Asia/Singapore",
      ipTzOff: 480,
      tz: "Asia/Shanghai",
      tzOff: 480,
      langs: ["zh-CN"],
      dnsCC: "SG",
      netKind: "mobile",
      dev: { os: "iOS" },
      exitsDone: true,
      exits: {
        ex_self: { ip: "9.9.9.42", cc: "SG", label: "新加坡 · CMLink" },
        ex_cn: { ip: "9.9.9.42", cc: "CN", label: "新加坡 · 新加坡 · 中国移动" },
        ex_intl: { ip: "9.9.9.42", cc: "SG", label: "新加坡" },
        ex_cf: { ip: "9.9.9.42", cc: "SG", colo: "SIN" },
      },
      stack: { v4: "9.9.9.42", v6: "" },
    },
  });
  const roamChecks = hRoam.check();
  assert.equal(roamChecks.split.level, "ok");
  assert.equal(roamChecks.tz.level, "warn");
  assert.match(roamChecks.tz.summary, /漫游/);
});

test("iOS 26/27+ frozen CPU iPhone OS 18_7 UA resolves real iOS version across Safari, WeChat, and CriOS", async () => {
  const base = harness();

  // 1) Safari on iOS 27.2.1 (Apple freezes CPU iPhone OS 18_7 and emits Version/27.2)
  const uaSaf272 = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Mobile/15E148 Safari/604.1";
  const dev272 = base.detectDevice(uaSaf272, {}, 5);
  assert.equal(dev272.os, "iOS");
  assert.equal(dev272.osv, "27.2");
  assert.equal(dev272.uaFrozenOs, "18.7");
  assert.deepEqual({ ...base.detectBrowser(uaSaf272, []) }, { name: "Safari", v: "27.2", inApp: false });

  // 2) Safari on iOS 27.0.1 (3-segment Version/27.0.1)
  const uaSaf2701 = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0.1 Mobile/15E148 Safari/604.1";
  assert.equal(base.detectDevice(uaSaf2701, {}, 5).osv, "27.0.1");

  // 3) WeChat in-app container on iOS 27.2.1 (UIDevice reports 27_2_1, no Version/)
  const uaWx2721 = "Mozilla/5.0 (iPhone; CPU iPhone OS 27_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.80(0x18005041)";
  assert.equal(base.detectDevice(uaWx2721, {}, 5).osv, "27.2.1");

  // 4) Extended security update iOS 16.7.16 where OS token is newer than Safari Version/16.6.2
  const uaIos167 = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_16 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6.2 Mobile/15E148 Safari/604.1";
  assert.equal(base.detectDevice(uaIos167, {}, 5).osv, "16.7.16");

  // 5) iPadOS 27.2 desktop-class Safari (Macintosh + maxTouchPoints > 1 + Version/27.2)
  const uaIpad272 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Safari/605.1.15";
  const devIpad = base.detectDevice(uaIpad272, {}, 5);
  assert.equal(devIpad.os, "iPadOS");
  assert.equal(devIpad.osv, "27.2");

  // 6) Chrome on iOS 27.2 (CriOS omits Version/ and inherits frozen CPU iPhone OS 18_7 -> WebKit ::field-content upgrades to 27.2+)
  const uaCriOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/148.0.6998.89 Mobile/15E148 Safari/604.1";
  const hCriOS = harness({
    mainPlatform: "iPhone",
    userAgent: uaCriOS,
    cssSupports: q => q === "selector(::field-content)" || q === "appearance: base-select" || q === "anchor-name: --a",
    state: { finished: true, values: {}, engine: "JavaScriptCore" },
  });
  await hCriOS.readHighEntropy();
  assert.equal(hCriOS.getState().osLabel, "iOS 27.2+ (iPhone)");

  // 7) Genuine iOS 18.7 without iOS 26/27 WebKit features stays 18.7
  const uaReal187 = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1";
  const hReal187 = harness({
    mainPlatform: "iPhone",
    userAgent: uaReal187,
    cssSupports: () => false,
    state: { finished: true, values: {}, engine: "JavaScriptCore" },
  });
  await hReal187.readHighEntropy();
  assert.equal(hReal187.getState().osLabel, "iOS 18.7 (iPhone)");
});
