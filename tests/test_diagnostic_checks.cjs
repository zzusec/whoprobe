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

function harness({ mainMemory, workerMemory, iframeMemory, mainPlatform = "MacIntel", shared, readings = {}, state = {} } = {}) {
  const userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)";
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
    "sceneBadge", "topGiveaway", "scoreSub", "issueCount", "cntBad", "cntWarn", "cntOk",
  ].map(id => [`#${id}`, {}]));
  const document = {
    querySelector: key => nodes[key] || null, querySelectorAll: () => [], addEventListener() {},
    createElement: tag => { assert.equal(tag, "iframe"); return iframe; }, body: { appendChild() {} }
  };
  const sandbox = {
    document, navigator, screen, window: { Worker, Blob }, Worker, Blob, URL, Intl,
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
    votes: { hosting: { of: 4, yes: 1, E: 0.35 }, proxy: { of: 4, E: 0 }, vpn: { of: 4, E: 0 }, tor: { of: 3, E: 0 } },
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
